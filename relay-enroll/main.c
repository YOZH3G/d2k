#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _DEFAULT_SOURCE /* MAP_ANONYMOUS on glibc */
#define _POSIX_C_SOURCE 200809L
#include "tg_identity.h"
#include "tg_net.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROOF_SIZE 120
#define MAX_CHILDREN 16
#define HEADER_LIMIT 4096
#define RESOLVE_BODY_LIMIT 2048
#define RESOLVE_MAX_NAMES 32
#define RESOLVE_MAX_ADDRESSES 8
#define RESOLVE_DEADLINE_SECONDS 10
/* glibc resolver bound per lookup: 2 s per server, one attempt. With at most
   two configured servers a lookup ends within RESOLVE_NAME_BUDGET seconds. */
#define RESOLVE_RES_OPTIONS "timeout:2 attempts:1"
#define RESOLVE_NAME_BUDGET 4
#define LOCK_WAIT_MS 1000
#define RESOLVE_REPLY_LIMIT 8192
#define REGISTER_PER_IP 6
#define REGISTER_TOTAL 120
#define RESOLVE_PER_IP 4
#define RESOLVE_TOTAL 60
#define RATE_SLOTS 120

enum { ROUTE_NONE, ROUTE_HEALTH, ROUTE_REGISTER, ROUTE_RESOLVE };

/* The only names /resolve answers. Public DNS data for a fixed Meta set; the
   router script and d2ktg --check-instagram-ip carry the same list, and
   scripts/test-instagram-dns.sh compares all three. */
static const char *const resolve_hosts[]={
    /* META_HOSTS_BEGIN */
    "instagram.com","www.instagram.com","graph.instagram.com","api.instagram.com",
    "i.instagram.com","instagram.c10r.instagram.com","static.cdninstagram.com",
    "scontent.cdninstagram.com","static.xx.fbcdn.net","scontent.xx.fbcdn.net",
    "web.whatsapp.com","www.whatsapp.com","scontent.whatsapp.net","graph.whatsapp.com",
    "v.whatsapp.com"
    /* META_HOSTS_END */
};

typedef struct { uint32_t ip; unsigned count; } ip_bucket;
typedef struct { time_t minute; unsigned total,used; ip_bucket ips[RATE_SLOTS]; } rate_limit;
/* Children decide by route after reading the request line, so the counters
   live in memory shared with every forked child. owner is the PID holding
   the lock (0: free). */
typedef struct { atomic_int owner; rate_limit registration,resolution; } shared_limits;
static volatile sig_atomic_t stopping;

static int rate_allow(rate_limit *limit,uint32_t ip,time_t now,unsigned per_ip,unsigned total) {
    time_t minute=now/60;
    if(limit->minute!=minute){memset(limit,0,sizeof(*limit));limit->minute=minute;}
    if(limit->total>=total||limit->total>=RATE_SLOTS)return 0;
    unsigned i;
    for(i=0;i<limit->used;i++)if(limit->ips[i].ip==ip)break;
    if(i==limit->used){limit->ips[i].ip=ip;limit->used++;}
    if(limit->ips[i].count>=per_ip)return 0;
    limit->ips[i].count++;limit->total++;return 1;
}

static shared_limits *shared_limits_create(void) {
    shared_limits *limits=mmap(NULL,sizeof(*limits),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(limits==MAP_FAILED)return NULL;
    memset(limits,0,sizeof(*limits));atomic_init(&limits->owner,0);return limits;
}

/* Signals are held only while the lock is owned, so the alarm can always end
   a waiting child. The critical section is a few instructions: a holder that
   is dead (SIGKILL, OOM) or that keeps the lock for the whole wait has lost
   it, and the lock is taken over instead of wedging every later child. */
static void limits_lock(shared_limits *limits,sigset_t *old) {
    sigset_t all;sigfillset(&all);
    int me=(int)getpid(),seen=0;
    for(int waited=0;;waited++){
        sigprocmask(SIG_BLOCK,&all,old);
        int expected=0;
        if(atomic_compare_exchange_strong(&limits->owner,&expected,me))return;
        if(waited==0)seen=expected;
        int stale=expected!=seen?0:(kill(expected,0)!=0&&errno==ESRCH)||waited>=LOCK_WAIT_MS;
        if(expected!=seen){seen=expected;waited=0;}
        if(stale&&atomic_compare_exchange_strong(&limits->owner,&expected,me))return;
        sigprocmask(SIG_SETMASK,old,NULL);
        struct timespec pause_ms={0,1000000};nanosleep(&pause_ms,NULL);
    }
}
static void limits_unlock(shared_limits *limits,const sigset_t *old) {
    atomic_store(&limits->owner,0);sigprocmask(SIG_SETMASK,old,NULL);
}

/* 200 when the route may proceed, 429 when its own counter is exhausted.
   /health is not counted. */
static int route_status(shared_limits *limits,int route,uint32_t ip,time_t now) {
    if(route!=ROUTE_REGISTER&&route!=ROUTE_RESOLVE)return 200;
    sigset_t old;limits_lock(limits,&old);
    int ok=route==ROUTE_REGISTER?
        rate_allow(&limits->registration,ip,now,REGISTER_PER_IP,REGISTER_TOTAL):
        rate_allow(&limits->resolution,ip,now,RESOLVE_PER_IP,RESOLVE_TOTAL);
    limits_unlock(limits,&old);
    return ok?200:429;
}

static int valid_proof(const uint8_t *body,size_t len) {
    uint8_t message[70],hash[SHA256_DIGEST_LENGTH];
    if(len!=PROOF_SIZE)return 0;
    memcpy(message,"d2k-enroll-v1",14);memcpy(message+14,body,56);
    if(!SHA256(message,sizeof(message),hash))return 0;
    return hash[0]==0&&hash[1]==0&&(hash[2]&0xc0)==0&&
        tg_identity_verify(body+16,message,sizeof(message),body+56)==0;
}

/* A strict, single-request HTTP parser. Transfer coding, duplicate lengths and
   extra bodies are unsupported. The connection always closes after one reply. */
static int parse_headers(char *headers,size_t *length,int *route) {
    *route=ROUTE_NONE;
    char *line=strstr(headers,"\r\n");if(!line)return 400;
    *line='\0';line+=2;
    if(strcmp(headers,"GET /health HTTP/1.1")==0){*route=ROUTE_HEALTH;return 204;}
    if(strcmp(headers,"POST /register HTTP/1.1")==0)*route=ROUTE_REGISTER;
    else if(strcmp(headers,"POST /resolve HTTP/1.1")==0)*route=ROUTE_RESOLVE;
    else return 404;
    int have_length=0;
    while(*line) {
        char *end=strstr(line,"\r\n");if(!end)return 400;*end='\0';
        if(!*line)break;
        char *colon=strchr(line,':');if(!colon)return 400;*colon++='\0';
        if(strcasecmp(line,"Transfer-Encoding")==0)return 400;
        if(strcasecmp(line,"Content-Length")==0) {
            if(have_length++)return 400;
            while(*colon==' '||*colon=='\t')colon++;
            if(*route==ROUTE_REGISTER){
                if(strcmp(colon,"120")!=0)return 400;
                *length=PROOF_SIZE;
            }else{
                /* Plain decimal, no sign, no leading zero, 1..2048. */
                size_t digits=strspn(colon,"0123456789");
                if(!digits||digits>4||colon[digits]||colon[0]=='0')return 400;
                unsigned long value=strtoul(colon,NULL,10);
                if(value>RESOLVE_BODY_LIMIT)return 400;
                *length=(size_t)value;
            }
        }
        line=end+2;
    }
    return have_length?200:400;
}

/* Writes up to cap IPv4 addresses (network order) for host; returns the count. */
typedef int (*resolve_fn)(const char *host,uint32_t *out,size_t cap);

static int system_resolve(const char *host,uint32_t *out,size_t cap) {
    struct addrinfo hints,*list=NULL;memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&hints,&list)!=0)return 0;
    size_t n=0;
    for(struct addrinfo *ai=list;ai&&n<cap;ai=ai->ai_next)
        if(ai->ai_family==AF_INET&&ai->ai_addrlen>=sizeof(struct sockaddr_in))
            out[n++]=((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(list);return (int)n;
}
static resolve_fn resolver=system_resolve; /* replaced by the tests */

static time_t monotonic_seconds(void) {
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts)!=0)return 0;return ts.tv_sec;
}
static time_t (*clock_now)(void)=monotonic_seconds; /* replaced by the tests */

static void json_space(const char **p,const char *end) {
    while(*p<end&&(**p==' '||**p=='\t'||**p=='\r'||**p=='\n'))(*p)++;
}
static int json_char(const char **p,const char *end,char c) {
    json_space(p,end);if(*p<end&&**p==c){(*p)++;return 1;}return 0;
}
/* Only escape-free strings of name characters; anything else is rejected. */
static int json_name(const char **p,const char *end,const char **start,size_t *len) {
    if(!json_char(p,end,'"'))return 0;
    *start=*p;
    while(*p<end&&**p!='"'){
        char c=**p;
        if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='-'))return 0;
        (*p)++;
    }
    if(*p>=end)return 0;
    *len=(size_t)(*p-*start);(*p)++;return *len>0;
}
static int allowed_host(const char *name,size_t len) {
    for(size_t i=0;i<sizeof(resolve_hosts)/sizeof(resolve_hosts[0]);i++)
        if(strlen(resolve_hosts[i])==len&&memcmp(resolve_hosts[i],name,len)==0)return (int)i;
    return -1;
}

/* Strict body {"hosts":[...]} → {"results":{"host":["a.b.c.d",...],...}}.
   deadline is a monotonic second (0: none). A name is looked up only while a
   whole bounded lookup still fits before it; the rest get [], so the reply is
   always sent before the connection's hard alarm. */
static int handle_resolve(const char *body,size_t length,char *out,size_t cap,size_t *out_len,time_t deadline) {
    const char *p=body,*end=body+length,*name;size_t name_len;
    int order[RESOLVE_MAX_NAMES];size_t count=0;int seen[sizeof(resolve_hosts)/sizeof(resolve_hosts[0])]={0};
    if(memchr(body,'\0',length))return 400;
    if(!json_char(&p,end,'{')||!json_name(&p,end,&name,&name_len)||name_len!=5||memcmp(name,"hosts",5)!=0||
       !json_char(&p,end,':')||!json_char(&p,end,'['))return 400;
    size_t total=0;
    do{
        if(!json_name(&p,end,&name,&name_len))return 400;
        int index=allowed_host(name,name_len);if(index<0)return 400;
        if(++total>RESOLVE_MAX_NAMES)return 400;
        if(!seen[index]){seen[index]=1;order[count++]=index;}
    }while(json_char(&p,end,','));
    if(!json_char(&p,end,']')||!json_char(&p,end,'}'))return 400;
    json_space(&p,end);if(p!=end)return 400;
    size_t used=0;int n;
#define EMIT(...) do{n=snprintf(out+used,cap-used,__VA_ARGS__);if(n<0||(size_t)n>=cap-used)return 502;used+=(size_t)n;}while(0)
    EMIT("{\"results\":{");
    for(size_t i=0;i<count;i++){
        const char *host=resolve_hosts[order[i]];
        uint32_t raw[32],unique[RESOLVE_MAX_ADDRESSES];size_t got=0,kept=0;
        if(!deadline||clock_now()+RESOLVE_NAME_BUDGET<=deadline){
            int r=resolver(host,raw,sizeof(raw)/sizeof(raw[0]));got=r>0?(size_t)r:0;
        }
        for(size_t j=0;j<got&&kept<RESOLVE_MAX_ADDRESSES;j++){
            size_t k;for(k=0;k<kept;k++)if(unique[k]==raw[j])break;
            if(k==kept)unique[kept++]=raw[j];
        }
        EMIT("%s\"%s\":[",i?",":"",host);
        for(size_t j=0;j<kept;j++){
            char text[INET_ADDRSTRLEN];struct in_addr a={.s_addr=unique[j]};
            if(!inet_ntop(AF_INET,&a,text,sizeof(text)))return 502;
            EMIT("%s\"%s\"",j?",":"",text);
        }
        EMIT("]");
    }
    EMIT("}}");
#undef EMIT
    *out_len=used;return 200;
}

static int socket_write_all(int fd,const char *data,size_t length) {
    while(length){ssize_t n=send(fd,data,length,0);if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        data+=n;length-=(size_t)n;}return 0;
}

static int forward_registration(const char *secret,const char *peer,const uint8_t *proof,uint16_t port) {
    static const char hex[]="0123456789abcdef";
    char id[33],pub[45],body[180],auth[65],request[1024],response[1024];
    for(size_t i=0;i<16;i++){id[2*i]=hex[proof[i]>>4];id[2*i+1]=hex[proof[i]&15];}id[32]='\0';
    if(EVP_EncodeBlock((unsigned char *)pub,proof+16,32)!=44)return 502;
    pub[44]='\0';
    int size=snprintf(body,sizeof(body),"{\"install_id\":\"%s\",\"pubkey\":\"%s\"}",id,pub);
    if(size<0||(size_t)size>=sizeof(body)||tg_register_hmac_hex(secret,body,(size_t)size,auth)!=0)return 502;
    int n=snprintf(request,sizeof(request),
        "POST /register HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
        "X-Z2K-Auth: %s\r\nX-Forwarded-For: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        auth,peer,size,body);
    OPENSSL_cleanse(auth,sizeof(auth));
    if(n<=0||(size_t)n>=sizeof(request))return 502;
    int fd=tg_tcp_connect_ipv4("127.0.0.1",port,8000);if(fd<0)return 502;
    int ok=socket_write_all(fd,request,(size_t)n)==0;OPENSSL_cleanse(request,sizeof(request));
    size_t used=0;
    while(ok&&used<sizeof(response)-1) {
        ssize_t got=recv(fd,response+used,1,0);if(got<0&&errno==EINTR)continue;
        if(got!=1){ok=0;break;}used++;
        if(used>=2&&memcmp(response+used-2,"\r\n",2)==0)break;
    }
    close(fd);response[used]='\0';int code=0;
    if(!ok||sscanf(response,"HTTP/1.%*1[01] %3d",&code)!=1)return 502;
    return code==200||code==409||code==429?code:502;
}

static void ssl_write_all(SSL *ssl,const char *data,size_t length) {
    size_t off=0;
    while(off<length){size_t sent=0;if(SSL_write_ex(ssl,data+off,length-off,&sent)!=1||!sent)break;off+=sent;}
}

static void reply_json(SSL *ssl,const char *body,size_t length) {
    char head[256];
    int n=snprintf(head,sizeof(head),"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",length);
    if(n<=0||(size_t)n>=sizeof(head))return;
    ssl_write_all(ssl,head,(size_t)n);ssl_write_all(ssl,body,length);
}

static void reply(SSL *ssl,int code) {
    const char *reason=code==200?"OK":code==204?"No Content":code==400?"Bad Request":
        code==404?"Not Found":code==409?"Conflict":code==429?"Too Many Requests":"Bad Gateway";
    char response[256];
    int n=snprintf(response,sizeof(response),"HTTP/1.1 %d %s\r\nContent-Length: 0\r\n"
        "Cache-Control: no-store\r\n%sConnection: close\r\n\r\n",code,reason,
        code==429?"Retry-After: 60\r\n":"");
    if(n>0&&(size_t)n<sizeof(response))ssl_write_all(ssl,response,(size_t)n);
}

static void serve_client(int fd,const char *peer,uint32_t peer_ip,shared_limits *limits,const char *certificate,
                         const char *key,const char *secret,uint16_t upstream_port) {
    /* A wall-clock limit also bounds byte-at-a-time slow senders and DNS. */
    alarm(12);
    time_t deadline=monotonic_seconds()+RESOLVE_DEADLINE_SECONDS;
    struct timeval timeout={.tv_sec=8,.tv_usec=0};
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());SSL *ssl=NULL;
    if(!ctx||SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION)!=1||
       SSL_CTX_use_certificate_chain_file(ctx,certificate)!=1||
       SSL_CTX_use_PrivateKey_file(ctx,key,SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(ctx)!=1)goto done;
    ssl=SSL_new(ctx);if(!ssl||SSL_set_fd(ssl,fd)!=1||SSL_accept(ssl)!=1)goto done;
    char headers[HEADER_LIMIT+1];size_t used=0,length=0;
    while(used<HEADER_LIMIT){size_t n=0;if(SSL_read_ex(ssl,headers+used,1,&n)!=1||n!=1)goto done;used++;
        if(used>=4&&memcmp(headers+used-4,"\r\n\r\n",4)==0)break;}
    if(used==HEADER_LIMIT){reply(ssl,400);goto done;}headers[used]='\0';
    /* Embedded NUL must not hide a header from the parser. */
    if(strlen(headers)!=used){reply(ssl,400);goto done;}
    int route=ROUTE_NONE;
    int code=parse_headers(headers,&length,&route);
    /* Each route spends only its own counter, also on malformed requests. */
    if(route_status(limits,route,peer_ip,time(NULL))==429){reply(ssl,429);goto done;}
    if(code!=200){reply(ssl,code);goto done;}
    if(route==ROUTE_RESOLVE){
        char body[RESOLVE_BODY_LIMIT],out[RESOLVE_REPLY_LIMIT];size_t out_len=0;used=0;
        while(used<length){size_t n=0;if(SSL_read_ex(ssl,body+used,length-used,&n)!=1||!n)goto done;used+=n;}
        code=handle_resolve(body,length,out,sizeof(out),&out_len,deadline);
        if(code==200)reply_json(ssl,out,out_len);else reply(ssl,code);
        goto done;
    }
    uint8_t proof[PROOF_SIZE];used=0;
    while(used<length){size_t n=0;if(SSL_read_ex(ssl,proof+used,length-used,&n)!=1||!n)goto done;used+=n;}
    if(!valid_proof(proof,used)){reply(ssl,400);goto done;}
    reply(ssl,forward_registration(secret,peer,proof,upstream_port));
done:
    SSL_free(ssl);SSL_CTX_free(ctx);close(fd);
}

static void stop_server(int signal_number){(void)signal_number;stopping=1;}
static void child_exited(int signal_number){(void)signal_number;}

int main(int argc,char **argv) {
    const char *certificate="/var/lib/z2k-relay/acme/213.176.74.63.nip.io",*key=NULL,*bootstrap=NULL;
    uint16_t port=9443,upstream=8080;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--certificate")==0&&i+1<argc)certificate=argv[++i];
        else if(strcmp(argv[i],"--key")==0&&i+1<argc)key=argv[++i];
        else if(strcmp(argv[i],"--bootstrap-file")==0&&i+1<argc)bootstrap=argv[++i];
        else if((strcmp(argv[i],"--port")==0||strcmp(argv[i],"--upstream-port")==0)&&i+1<argc){
            int is_up=strcmp(argv[i],"--upstream-port")==0;char *end;
            unsigned long value=strtoul(argv[++i],&end,10);if(!value||value>65535||*end)return 2;
            if(is_up)upstream=(uint16_t)value;else port=(uint16_t)value;
        }else return 2;
    }
    if(!bootstrap){fputs("bootstrap credential path required\n",stderr);return 2;}
    if(!key)key=certificate;
    char secret[1024];int credential=open(bootstrap,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(credential<0||fstat(credential,&st)!=0||!S_ISREG(st.st_mode)||st.st_size<1||st.st_size>=(off_t)sizeof(secret)){
        fputs("cannot read server credential\n",stderr);if(credential>=0)close(credential);return 1;
    }
    ssize_t n=read(credential,secret,sizeof(secret)-1);close(credential);if(n!=st.st_size)return 1;
    while(n>0&&isspace((unsigned char)secret[n-1]))n--;
    secret[n]='\0';if(n==0)return 1;
    /* Validate the PEM before declaring the service ready. Each child reloads
       it for renewals, without restarting the existing shared relay. */
    SSL_CTX *check=SSL_CTX_new(TLS_server_method());
    if(!check||SSL_CTX_use_certificate_chain_file(check,certificate)!=1||
       SSL_CTX_use_PrivateKey_file(check,key,SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(check)!=1){
        SSL_CTX_free(check);fputs("cannot load relay TLS certificate\n",stderr);return 1;}
    SSL_CTX_free(check);
    struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_handler=stop_server;
    (void)sigaction(SIGTERM,&sa,NULL);(void)sigaction(SIGINT,&sa,NULL);
    /* Children read it on their first lookup; an operator's value wins. */
    (void)setenv("RES_OPTIONS",RESOLVE_RES_OPTIONS,0);
    sa.sa_handler=child_exited;(void)sigaction(SIGCHLD,&sa,NULL);(void)signal(SIGPIPE,SIG_IGN);
    int listener=socket(AF_INET,SOCK_STREAM,0),one=1;if(listener<0)return 1;
    (void)setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    if(bind(listener,(struct sockaddr *)&addr,sizeof(addr))!=0||listen(listener,32)!=0){close(listener);perror("enrollment listener");return 1;}
    fprintf(stderr,"D2K C enrollment listening on %u\n",(unsigned)port);
    unsigned children=0;shared_limits *limits=shared_limits_create();
    if(!limits){close(listener);fputs("cannot allocate rate limits\n",stderr);return 1;}
    while(!stopping){
        while(waitpid(-1,NULL,WNOHANG)>0)if(children)children--;
        struct sockaddr_in peer;socklen_t peer_len=sizeof(peer);
        int fd=accept(listener,(struct sockaddr *)&peer,&peer_len);
        if(fd<0){if(errno==EINTR)continue;break;}
        if(children>=MAX_CHILDREN){close(fd);continue;}
        char ip[INET_ADDRSTRLEN];if(!inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip))){close(fd);continue;}
        pid_t pid=fork();
        if(pid==0){close(listener);(void)signal(SIGTERM,SIG_DFL);(void)signal(SIGINT,SIG_DFL);
            serve_client(fd,ip,peer.sin_addr.s_addr,limits,certificate,key,secret,upstream);OPENSSL_cleanse(secret,sizeof(secret));_exit(0);}
        close(fd);if(pid>0)children++;
    }
    close(listener);OPENSSL_cleanse(secret,sizeof(secret));return 0;
}
