#define _POSIX_C_SOURCE 200809L
#include "tg_identity.h"
#include "tg_net.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROOF_SIZE 120
#define MAX_CHILDREN 16
#define HEADER_LIMIT 4096

typedef struct { uint32_t ip; unsigned count; } ip_bucket;
typedef struct { time_t minute; unsigned total,used; ip_bucket ips[120]; } rate_limit;
static volatile sig_atomic_t stopping;

static int rate_allow(rate_limit *limit,uint32_t ip,time_t now) {
    time_t minute=now/60;
    if(limit->minute!=minute){memset(limit,0,sizeof(*limit));limit->minute=minute;}
    if(limit->total>=120)return 0;
    unsigned i;
    for(i=0;i<limit->used;i++)if(limit->ips[i].ip==ip)break;
    if(i==limit->used){limit->ips[i].ip=ip;limit->used++;}
    if(limit->ips[i].count>=6)return 0;
    limit->ips[i].count++;limit->total++;return 1;
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
static int parse_headers(char *headers,size_t *length) {
    char *line=strstr(headers,"\r\n");if(!line)return 400;
    *line='\0';line+=2;
    if(strcmp(headers,"GET /health HTTP/1.1")==0)return 204;
    if(strcmp(headers,"POST /register HTTP/1.1")!=0)return 404;
    int have_length=0;
    while(*line) {
        char *end=strstr(line,"\r\n");if(!end)return 400;*end='\0';
        if(!*line)break;
        char *colon=strchr(line,':');if(!colon)return 400;*colon++='\0';
        if(strcasecmp(line,"Transfer-Encoding")==0)return 400;
        if(strcasecmp(line,"Content-Length")==0) {
            if(have_length++)return 400;
            while(*colon==' '||*colon=='\t')colon++;
            if(strcmp(colon,"120")!=0)return 400;
            *length=PROOF_SIZE;
        }
        line=end+2;
    }
    return have_length?200:400;
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

static void reply(SSL *ssl,int code) {
    const char *reason=code==200?"OK":code==204?"No Content":code==400?"Bad Request":
        code==404?"Not Found":code==409?"Conflict":code==429?"Too Many Requests":"Bad Gateway";
    char response[256];
    int n=snprintf(response,sizeof(response),"HTTP/1.1 %d %s\r\nContent-Length: 0\r\n"
        "Cache-Control: no-store\r\n%sConnection: close\r\n\r\n",code,reason,
        code==429?"Retry-After: 60\r\n":"");
    if(n>0&&(size_t)n<sizeof(response)){
        size_t off=0;while(off<(size_t)n){size_t sent=0;if(SSL_write_ex(ssl,response+off,(size_t)n-off,&sent)!=1||!sent)break;off+=sent;}
    }
}

static void serve_client(int fd,const char *peer,int allowed,const char *certificate,
                         const char *key,const char *secret,uint16_t upstream_port) {
    /* A wall-clock limit also bounds byte-at-a-time slow senders. */
    alarm(12);
    struct timeval timeout={.tv_sec=8,.tv_usec=0};
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());SSL *ssl=NULL;
    if(!ctx||SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION)!=1||
       SSL_CTX_use_certificate_chain_file(ctx,certificate)!=1||
       SSL_CTX_use_PrivateKey_file(ctx,key,SSL_FILETYPE_PEM)!=1||SSL_CTX_check_private_key(ctx)!=1)goto done;
    ssl=SSL_new(ctx);if(!ssl||SSL_set_fd(ssl,fd)!=1||SSL_accept(ssl)!=1)goto done;
    if(!allowed){reply(ssl,429);goto done;}
    char headers[HEADER_LIMIT+1];size_t used=0,length=0;
    while(used<HEADER_LIMIT){size_t n=0;if(SSL_read_ex(ssl,headers+used,1,&n)!=1||n!=1)goto done;used++;
        if(used>=4&&memcmp(headers+used-4,"\r\n\r\n",4)==0)break;}
    if(used==HEADER_LIMIT){reply(ssl,400);goto done;}headers[used]='\0';
    /* Embedded NUL must not hide a header from the parser. */
    if(strlen(headers)!=used){reply(ssl,400);goto done;}
    int code=parse_headers(headers,&length);
    if(code!=200){reply(ssl,code);goto done;}
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
    sa.sa_handler=child_exited;(void)sigaction(SIGCHLD,&sa,NULL);(void)signal(SIGPIPE,SIG_IGN);
    int listener=socket(AF_INET,SOCK_STREAM,0),one=1;if(listener<0)return 1;
    (void)setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    if(bind(listener,(struct sockaddr *)&addr,sizeof(addr))!=0||listen(listener,32)!=0){close(listener);perror("enrollment listener");return 1;}
    fprintf(stderr,"D2K C enrollment listening on %u\n",(unsigned)port);
    unsigned children=0;rate_limit limit={0};
    while(!stopping){
        while(waitpid(-1,NULL,WNOHANG)>0)if(children)children--;
        struct sockaddr_in peer;socklen_t peer_len=sizeof(peer);
        int fd=accept(listener,(struct sockaddr *)&peer,&peer_len);
        if(fd<0){if(errno==EINTR)continue;break;}
        if(children>=MAX_CHILDREN){close(fd);continue;}
        char ip[INET_ADDRSTRLEN];if(!inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip))){close(fd);continue;}
        int allowed=rate_allow(&limit,peer.sin_addr.s_addr,time(NULL));
        pid_t pid=fork();
        if(pid==0){close(listener);(void)signal(SIGTERM,SIG_DFL);(void)signal(SIGINT,SIG_DFL);
            serve_client(fd,ip,allowed,certificate,key,secret,upstream);OPENSSL_cleanse(secret,sizeof(secret));_exit(0);}
        close(fd);if(pid>0)children++;
    }
    close(listener);OPENSSL_cleanse(secret,sizeof(secret));return 0;
}
