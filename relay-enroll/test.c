#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define main enrollment_program_main
#include "main.c"
#undef main
#include "tg_enroll.h"
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static void test_proof(void) {
    char directory[]="/tmp/d2k-enroll-server-XXXXXX",path[256];assert(mkdtemp(directory));
    snprintf(path,sizeof(path),"%s/identity",directory);
    tg_identity identity={0};assert(tg_identity_load_or_mint(path,&identity)==0);
    uint8_t body[PROOF_SIZE];assert(tg_enroll_proof(&identity,body)==0);
    assert(valid_proof(body,sizeof(body)));
    const size_t offsets[]={0,16,48,56,119};
    for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++){
        body[offsets[i]]^=1;assert(!valid_proof(body,sizeof(body)));body[offsets[i]]^=1;
    }
    assert(!valid_proof(body,119));assert(!valid_proof(body,121));
    tg_identity_cleanup(&identity);unlink(path);rmdir(directory);
}

static void test_rate_limit(void) {
    rate_limit limit={0};time_t now=120;
    for(int i=0;i<6;i++)assert(rate_allow(&limit,1,now,REGISTER_PER_IP,REGISTER_TOTAL));
    assert(!rate_allow(&limit,1,now,REGISTER_PER_IP,REGISTER_TOTAL));
    for(int i=6;i<120;i++)assert(rate_allow(&limit,(uint32_t)i,now,REGISTER_PER_IP,REGISTER_TOTAL));
    assert(!rate_allow(&limit,200,now,REGISTER_PER_IP,REGISTER_TOTAL));
    assert(rate_allow(&limit,1,now+60,REGISTER_PER_IP,REGISTER_TOTAL));
}

/* /resolve and /register keep separate counters: exhausting one never
   throttles the other, and an exhausted route answers 429. */
static void test_route_limits(void) {
    shared_limits *limits=shared_limits_create();assert(limits);time_t now=600;
    for(int i=0;i<REGISTER_PER_IP;i++)assert(route_status(limits,ROUTE_REGISTER,7,now)==200);
    assert(route_status(limits,ROUTE_REGISTER,7,now)==429);
    for(int i=0;i<RESOLVE_PER_IP;i++)assert(route_status(limits,ROUTE_RESOLVE,7,now)==200);
    assert(route_status(limits,ROUTE_RESOLVE,7,now)==429);
    assert(route_status(limits,ROUTE_RESOLVE,8,now)==200);
    assert(route_status(limits,ROUTE_HEALTH,7,now)==200);
    /* Counters live in shared memory: a forked child's use is seen by the parent. */
    pid_t child=fork();assert(child>=0);
    if(child==0){_exit(route_status(limits,ROUTE_RESOLVE,9,now)==200?0:1);}
    int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    for(int i=1;i<RESOLVE_PER_IP;i++)assert(route_status(limits,ROUTE_RESOLVE,9,now)==200);
    assert(route_status(limits,ROUTE_RESOLVE,9,now)==429);
    assert(route_status(limits,ROUTE_RESOLVE,7,now+60)==200);
}

static const char *fake_answers[][3]={
    {"instagram.com","157.240.0.174","57.144.248.34"},
    {"web.whatsapp.com","57.144.245.32",NULL},
    {"static.xx.fbcdn.net","157.240.205.11",NULL},
};
static int fake_calls;
static int fake_resolve(const char *host,uint32_t *out,size_t cap) {
    fake_calls++;size_t n=0;
    for(size_t i=0;i<sizeof(fake_answers)/sizeof(fake_answers[0]);i++){
        if(strcmp(host,fake_answers[i][0])!=0)continue;
        for(size_t j=1;j<3&&fake_answers[i][j]&&n<cap;j++){
            struct in_addr a;assert(inet_pton(AF_INET,fake_answers[i][j],&a)==1);out[n++]=a.s_addr;
            if(n<cap)out[n++]=a.s_addr; /* duplicates must be collapsed */
        }
    }
    if(strcmp(host,"v.whatsapp.com")==0)for(uint32_t i=0;i<12&&n<cap;i++)out[n++]=htonl(0x39900000u+i);
    return (int)n;
}

static int resolve_json(const char *body,char *out,size_t cap) {
    size_t used=0;return handle_resolve(body,strlen(body),out,cap,&used,0);
}

static void test_resolve(void) {
    resolver=fake_resolve;char out[RESOLVE_REPLY_LIMIT];
    assert(resolve_json("{\"hosts\":[\"instagram.com\",\"web.whatsapp.com\",\"static.xx.fbcdn.net\",\"i.instagram.com\"]}",out,sizeof(out))==200);
    assert(strcmp(out,"{\"results\":{\"instagram.com\":[\"157.240.0.174\",\"57.144.248.34\"],"
        "\"web.whatsapp.com\":[\"57.144.245.32\"],\"static.xx.fbcdn.net\":[\"157.240.205.11\"],"
        "\"i.instagram.com\":[]}}")==0);
    /* Whitespace is JSON; at most eight distinct addresses per name. */
    assert(resolve_json(" { \"hosts\" : [ \"v.whatsapp.com\" ] } ",out,sizeof(out))==200);
    assert(strstr(out,"\"57.144.0.7\"")&&!strstr(out,"\"57.144.0.8\""));
    /* Every name of the fixed list is accepted in one request. */
    char all[1024]="{\"hosts\":[";
    for(size_t i=0;i<sizeof(resolve_hosts)/sizeof(resolve_hosts[0]);i++){
        if(i)strcat(all,",");
        strcat(all,"\"");strcat(all,resolve_hosts[i]);strcat(all,"\"");}
    strcat(all,"]}");assert(sizeof(resolve_hosts)/sizeof(resolve_hosts[0])==18);
    assert(resolve_json(all,out,sizeof(out))==200);
    for(size_t i=0;i<sizeof(resolve_hosts)/sizeof(resolve_hosts[0]);i++){
        char key[96];snprintf(key,sizeof(key),"\"%s\":[",resolve_hosts[i]);assert(strstr(out,key));}
    const char *bad[]={
        "{\"hosts\":[\"example.com\"]}", "{\"hosts\":[\"instagram.com\",\"evil.example\"]}",
        "{\"hosts\":[\"INSTAGRAM.COM\"]}", "{\"hosts\":[\"instagram.com.\"]}",
        "{\"hosts\":[\"instagram\\u002ecom\"]}", "{\"hosts\":[]}", "{\"hosts\":\"instagram.com\"}",
        "{\"hosts\":[\"instagram.com\"],\"x\":1}", "{\"hosts\":[\"instagram.com\"]}x",
        "{\"hosts\":[\"instagram.com\",]}", "{\"hosts\":[\"instagram.com\"]", "", "[]",
        "{\"hosts\":[\"instagram.com\"],\"hosts\":[\"instagram.com\"]}"
    };
    int before=fake_calls;
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++)assert(resolve_json(bad[i],out,sizeof(out))==400);
    assert(fake_calls==before); /* a rejected request never reaches DNS */
    /* More than 32 names (repeats included) is rejected. */
    char many[2048]="{\"hosts\":[";
    for(int i=0;i<33;i++){if(i)strcat(many,",");strcat(many,"\"instagram.com\"");}
    strcat(many,"]}");assert(resolve_json(many,out,sizeof(out))==400);
    /* An expired deadline answers the remaining names without addresses. */
    size_t used=0;const char *one="{\"hosts\":[\"instagram.com\"]}";before=fake_calls;
    assert(handle_resolve(one,strlen(one),out,sizeof(out),&used,1)==200);
    assert(fake_calls==before&&strcmp(out,"{\"results\":{\"instagram.com\":[]}}")==0&&used==strlen(out));
    resolver=system_resolve;
}

/* M1: a name is started only when its bounded lookup can finish before the
   deadline, so the reply always precedes the hard alarm. */
static int64_t fake_ms;
static int64_t fake_clock(void){return fake_ms;}
static int slow_resolve(const char *host,uint32_t *out,size_t cap) {
    (void)host;fake_ms+=3000;if(!cap)return 0;out[0]=htonl(0x9df00001u);return 1;
}
static void test_resolve_budget(void) {
    resolver=slow_resolve;clock_ms=fake_clock;fake_ms=93000;
    const char *body="{\"hosts\":[\"instagram.com\",\"www.instagram.com\",\"graph.instagram.com\"]}";
    char out[RESOLVE_REPLY_LIMIT];size_t used=0;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,100)==200);
    assert(strcmp(out,"{\"results\":{\"instagram.com\":[\"157.240.0.1\"],"
        "\"www.instagram.com\":[\"157.240.0.1\"],\"graph.instagram.com\":[]}}")==0);
    assert(fake_ms==99000);
    resolver=system_resolve;clock_ms=monotonic_ms;
    /* Lookups are bounded per name: timeout 2 s, one attempt. */
    assert(strcmp(RESOLVE_RES_OPTIONS,"timeout:2 attempts:1")==0);
    assert(RESOLVE_NAME_BUDGET*1<=RESOLVE_DEADLINE_SECONDS);
}

/* M2: a holder that died inside the critical section cannot wedge the
   limiter; neither can a live process that never releases it. */
static void test_lock_recovery(void) {
    shared_limits *limits=shared_limits_create();assert(limits);
    pid_t dead=fork();assert(dead>=0);if(dead==0)_exit(0);
    assert(waitpid(dead,NULL,0)==dead);
    atomic_store(&limits->owner,(int)dead);
    assert(route_status(limits,ROUTE_RESOLVE,5,600)==200);
    assert(atomic_load(&limits->owner)==0);
    pid_t stuck=fork();assert(stuck>=0);if(stuck==0){pause();_exit(0);}
    atomic_store(&limits->owner,(int)stuck);
    time_t began=time(NULL);
    assert(route_status(limits,ROUTE_RESOLVE,5,600)==200);
    assert(time(NULL)-began<=3&&atomic_load(&limits->owner)==0);
    kill(stuck,SIGKILL);waitpid(stuck,NULL,0);
}

/* M5: the full request path (TLS, headers, route counter, body, reply). */
static char cert_path[64];
static void make_cert(void) {
    strcpy(cert_path,"/tmp/d2k-enroll-cert-XXXXXX");int fd=mkstemp(cert_path);assert(fd>=0);
    EVP_PKEY *key=EVP_EC_gen("P-256");assert(key);X509 *x=X509_new();assert(x);
    assert(X509_set_version(x,2)==1&&ASN1_INTEGER_set(X509_get_serialNumber(x),1)==1);
    assert(X509_gmtime_adj(X509_getm_notBefore(x),0)&&X509_gmtime_adj(X509_getm_notAfter(x),3600));
    assert(X509_set_pubkey(x,key)==1);X509_NAME *name=X509_get_subject_name(x);
    assert(X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char *)"localhost",-1,-1,0)==1);
    assert(X509_set_issuer_name(x,name)==1&&X509_sign(x,key,EVP_sha256())>0);
    FILE *f=fdopen(fd,"w");assert(f);
    assert(PEM_write_X509(f,x)==1&&PEM_write_PrivateKey(f,key,NULL,NULL,0,NULL,NULL)==1);
    fclose(f);X509_free(x);EVP_PKEY_free(key);
}
static int full_request(shared_limits *limits,uint32_t ip,const char *request,size_t length,char *reply,size_t cap) {
    int sv[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
    pid_t child=fork();assert(child>=0);
    if(child==0){close(sv[0]);serve_client(sv[1],"192.0.2.9",ip,limits,cert_path,cert_path,"test-only",1);_exit(0);}
    close(sv[1]);
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());assert(ctx);SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
    SSL *ssl=SSL_new(ctx);assert(ssl&&SSL_set_fd(ssl,sv[0])==1&&SSL_connect(ssl)==1);
    size_t sent=0;assert(SSL_write_ex(ssl,request,length,&sent)==1&&sent==length);
    size_t used=0;
    for(;;){size_t n=0;if(SSL_read_ex(ssl,reply+used,cap-1-used,&n)!=1||!n)break;used+=n;assert(used<cap-1);}
    reply[used]='\0';SSL_free(ssl);SSL_CTX_free(ctx);close(sv[0]);
    int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status));
    int code=0;assert(sscanf(reply,"HTTP/1.1 %3d",&code)==1);return code;
}
static int post(shared_limits *limits,uint32_t ip,const char *path,const char *body,size_t length,char *reply,size_t cap) {
    char request[4096];
    int n=snprintf(request,sizeof(request),"POST %s HTTP/1.1\r\nHost: relay\r\nContent-Length: %zu\r\n\r\n",path,length);
    assert(n>0&&(size_t)n+length<sizeof(request));memcpy(request+n,body,length);
    return full_request(limits,ip,request,(size_t)n+length,reply,cap);
}
static void test_full_path(void) {
    make_cert();resolver=fake_resolve;
    shared_limits *limits=shared_limits_create();assert(limits);
    char reply[8192];const char *good="{\"hosts\":[\"instagram.com\"]}",*bad="{\"hosts\":[\"example.com\"]}";
    /* Malformed /resolve requests (headers or body) spend its counter too. */
    const char dup[]="POST /resolve HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
    assert(full_request(limits,11,dup,sizeof(dup)-1,reply,sizeof(reply))==400);
    assert(post(limits,11,"/resolve",bad,strlen(bad),reply,sizeof(reply))==400);
    for(int i=2;i<RESOLVE_PER_IP;i++){
        assert(post(limits,11,"/resolve",good,strlen(good),reply,sizeof(reply))==200);
        assert(strstr(reply,"Content-Type: application/json\r\n"));
        assert(strstr(reply,"\r\n\r\n{\"results\":{\"instagram.com\":[\"157.240.0.174\",\"57.144.248.34\"]}}"));
    }
    assert(post(limits,11,"/resolve",good,strlen(good),reply,sizeof(reply))==429);
    assert(strstr(reply,"Retry-After: 60\r\n")&&!strstr(reply,"results"));
    /* Other peers and the /register counter are unaffected. */
    assert(post(limits,12,"/resolve",good,strlen(good),reply,sizeof(reply))==200);
    uint8_t proof[PROOF_SIZE]={0};
    assert(post(limits,11,"/register",(const char *)proof,sizeof(proof),reply,sizeof(reply))==400);
    const char health[]="GET /health HTTP/1.1\r\nHost: relay\r\n\r\n";
    assert(full_request(limits,11,health,sizeof(health)-1,reply,sizeof(reply))==204);
    resolver=system_resolve;unlink(cert_path);
}

/* ---- Task 45: several independent resolvers ---------------------------- */

/* A scripted DNS server behind the transport hook. Each public resolver has a
   behaviour; replies are built from the real query, so IDs and questions are
   whatever the code under test sent. */
enum { SRV_OK, SRV_SILENT, SRV_BAD_ID, SRV_TRUNCATED, SRV_GARBAGE };
typedef struct { size_t server; uint8_t data[512]; size_t len; } fake_datagram;
static int srv_mode[PUBLIC_RESOLVERS];
static uint32_t srv_first[PUBLIC_RESOLVERS]; /* first address per server */
static unsigned srv_count[PUBLIC_RESOLVERS]; /* addresses per answer */
static fake_datagram fake_queue[RESOLVE_MAX_NAMES*PUBLIC_RESOLVERS*2];
static size_t fake_head,fake_tail,fake_sent;
static int fake_silent_advances; /* recv on an empty queue moves the fake clock */

static size_t put16(uint8_t *p,size_t off,unsigned v){p[off]=(uint8_t)(v>>8);p[off+1]=(uint8_t)v;return off+2;}
static size_t put_name(uint8_t *p,size_t off,const char *name) {
    while(*name){const char *dot=strchr(name,'.');size_t n=dot?(size_t)(dot-name):strlen(name);
        p[off++]=(uint8_t)n;memcpy(p+off,name,n);off+=n;name+=n;if(*name=='.')name++;}
    p[off++]=0;return off;
}
/* Reply = header + echoed question + answers; owner 0xC00C is the question. */
static size_t fake_reply(const uint8_t *q,size_t qlen,int mode,uint32_t first,unsigned count,uint8_t *r) {
    memcpy(r,q,qlen);r[2]|=0x80;r[3]=0x80;size_t off=qlen;unsigned answers=0;
    if(mode==SRV_BAD_ID){r[0]^=0x5a;}
    if(mode==SRV_TRUNCATED)r[2]|=0x02;
    for(unsigned i=0;i<count;i++){
        off=put16(r,off,0xc00cu);
        off=put16(r,off,1);off=put16(r,off,1);off=put16(r,off,0);off=put16(r,off,60);off=put16(r,off,4);
        uint32_t a=htonl(ntohl(first)+i);memcpy(r+off,&a,4);off+=4;answers++;
    }
    put16(r,6,answers);
    if(mode==SRV_GARBAGE){put16(r,6,3);off=qlen+5;} /* answer count beyond the data */
    return off;
}
static int fake_send(void *ctx,size_t server,const uint8_t *query,size_t len) {
    (void)ctx;fake_sent++;assert(server<PUBLIC_RESOLVERS&&len<=300);
    if(srv_mode[server]==SRV_SILENT)return 0;
    fake_datagram *d=&fake_queue[fake_tail++];d->server=server;
    d->len=fake_reply(query,len,srv_mode[server],srv_first[server],srv_count[server],d->data);
    return 0;
}
static int fake_recv(void *ctx,size_t *server,uint8_t *buf,size_t cap,int timeout_ms) {
    (void)ctx;
    if(fake_head==fake_tail){if(!fake_silent_advances)return -1;fake_ms+=timeout_ms;return 0;}
    fake_datagram *d=&fake_queue[fake_head++];assert(d->len<=cap);memcpy(buf,d->data,d->len);*server=d->server;return (int)d->len;
}
static int fake_open(void *ctx){(void)ctx;fake_head=fake_tail=fake_sent=0;return 0;}
static void fake_close(void *ctx){(void)ctx;}
static dns_transport fake_dns={NULL,fake_open,fake_send,fake_recv,fake_close};
static int no_open(void *ctx){(void)ctx;return -1;}
static dns_transport no_dns={NULL,no_open,fake_send,fake_recv,fake_close};

static void test_dns_parse(void) {
    uint8_t q[300],r[512];size_t qlen=dns_build_query(0x1234,"static.whatsapp.net",q,sizeof(q));
    assert(qlen==12+21+4&&q[0]==0x12&&q[1]==0x34&&q[2]==0x01&&q[5]==1);
    uint32_t out[8];
    size_t rlen=fake_reply(q,qlen,SRV_OK,htonl(0x3990f520u),2,r);
    assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)==2);
    assert(out[0]==htonl(0x3990f520u)&&out[1]==htonl(0x3990f521u));
    assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,1)==1); /* cap */
    rlen=fake_reply(q,qlen,SRV_BAD_ID,htonl(0x3990f520u),1,r);
    assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);
    rlen=fake_reply(q,qlen,SRV_TRUNCATED,htonl(0x3990f520u),1,r);
    assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);
    rlen=fake_reply(q,qlen,SRV_GARBAGE,htonl(0x3990f520u),1,r);
    assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);
    /* Every truncation of a valid reply is rejected or yields only whole records. */
    rlen=fake_reply(q,qlen,SRV_OK,htonl(0x3990f520u),2,r);
    for(size_t cut=0;cut<rlen;cut++)assert(dns_parse_reply(r,cut,q,qlen,"static.whatsapp.net",out,8)<0);
    /* Wrong question, error rcode, not a response, a second question. */
    uint8_t other[300];size_t olen=dns_build_query(0x1234,"web.whatsapp.com",other,sizeof(other));
    assert(dns_parse_reply(r,rlen,other,olen,"web.whatsapp.com",out,8)<0);
    r[3]=0x83;assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);r[3]=0x80;
    r[2]&=0x7f;assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);r[2]|=0x80;
    r[5]=2;assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);r[5]=1;
    /* An A record whose rdata is not 4 bytes, or of another class, is ignored. */
    rlen=fake_reply(q,qlen,SRV_OK,htonl(0x3990f520u),1,r);
    r[qlen+2+2+1]=3;assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)==0);
    /* A compression pointer loop is rejected. */
    rlen=fake_reply(q,qlen,SRV_OK,htonl(0x3990f520u),1,r);
    put16(r,qlen,0xc000|(unsigned)qlen);assert(dns_parse_reply(r,rlen,q,qlen,"static.whatsapp.net",out,8)<0);
}

static void test_dns_cname_chain(void) {
    uint8_t q[300],r[512];size_t qlen=dns_build_query(7,"web.whatsapp.com",q,sizeof(q));
    /* Hand-built: web CNAME a.example; a.example CNAME b.example;
       other.example A 6.6.6.6 (not on the chain); b.example A 1.2.3.4. */
    memcpy(r,q,qlen);r[2]|=0x80;r[3]=0x80;size_t off=qlen;
    off=put16(r,off,0xc00c);off=put16(r,off,5);off=put16(r,off,1);off=put16(r,off,0);off=put16(r,off,60);
    size_t rd=off;off+=2;size_t a_name=off;off=put_name(r,off,"a.example");put16(r,rd,(unsigned)(off-rd-2));
    off=put16(r,off,0xc000|(unsigned)a_name);off=put16(r,off,5);off=put16(r,off,1);off=put16(r,off,0);off=put16(r,off,60);
    rd=off;off+=2;size_t b_name=off;off=put_name(r,off,"b.example");put16(r,rd,(unsigned)(off-rd-2));
    off=put_name(r,off,"other.example");off=put16(r,off,1);off=put16(r,off,1);off=put16(r,off,0);off=put16(r,off,60);
    off=put16(r,off,4);r[off++]=6;r[off++]=6;r[off++]=6;r[off++]=6;
    off=put16(r,off,0xc000|(unsigned)b_name);off=put16(r,off,1);off=put16(r,off,1);off=put16(r,off,0);off=put16(r,off,60);
    off=put16(r,off,4);r[off++]=1;r[off++]=2;r[off++]=3;r[off++]=4;
    put16(r,6,4);
    uint32_t out[8];assert(dns_parse_reply(r,off,q,qlen,"web.whatsapp.com",out,8)==1);
    assert(out[0]==htonl(0x01020304u));
    /* A CNAME pointing back to itself does not loop. */
    put16(r,qlen+10,2);put16(r,qlen+12,0xc00c);put16(r,6,1);
    assert(dns_parse_reply(r,qlen+14,q,qlen,"web.whatsapp.com",out,8)==0);
}

static uint32_t sys_answer;
static int one_system(const char *host,uint32_t *out,size_t cap) {
    (void)host;if(!cap||!sys_answer)return 0;out[0]=sys_answer;return 1;
}

static void test_resolver_union(void) {
    char out[RESOLVE_REPLY_LIMIT];size_t used=0;
    const char *body="{\"hosts\":[\"static.whatsapp.net\",\"web.whatsapp.com\"]}";
    resolver=one_system;public_dns=&fake_dns;clock_ms=fake_clock;fake_silent_advances=0;
    /* VPS GeoDNS gives the dead 157.240.0.60; the public resolvers add others;
       repeats collapse; system answer first, then resolvers in order. */
    sys_answer=htonl(0x9df0003cu);fake_ms=0;
    srv_mode[0]=SRV_OK;srv_first[0]=htonl(0x3990f520u);srv_count[0]=1;   /* 57.144.245.32 */
    srv_mode[1]=SRV_OK;srv_first[1]=htonl(0x9df0003cu);srv_count[1]=1;   /* duplicate of system */
    srv_mode[2]=SRV_OK;srv_first[2]=htonl(0x1f0d4834u);srv_count[2]=1;   /* 31.13.72.52 */
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,100)==200);
    assert(strcmp(out,"{\"results\":{\"static.whatsapp.net\":[\"157.240.0.60\",\"57.144.245.32\",\"31.13.72.52\"],"
        "\"web.whatsapp.com\":[\"157.240.0.60\",\"57.144.245.32\",\"31.13.72.52\"]}}")==0);
    assert(fake_sent==2*PUBLIC_RESOLVERS);
    /* At most eight per name. */
    srv_count[0]=5;srv_count[1]=5;srv_first[1]=htonl(0x0a000001u);srv_count[2]=5;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,100)==200);
    const char *first_list=strchr(out,'[');size_t commas=0;
    for(const char *c=first_list;*c&&*c!=']';c++)if(*c==',')commas++;
    assert(commas==7);
    /* Malformed, mismatched-ID and truncated answers are ignored; others count. */
    srv_count[0]=srv_count[1]=srv_count[2]=1;
    srv_mode[0]=SRV_BAD_ID;srv_mode[1]=SRV_TRUNCATED;srv_mode[2]=SRV_GARBAGE;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,100)==200);
    assert(strcmp(out,"{\"results\":{\"static.whatsapp.net\":[\"157.240.0.60\"],\"web.whatsapp.com\":[\"157.240.0.60\"]}}")==0);
    /* No public resolver reachable: the system answer alone. */
    public_dns=&no_dns;sys_answer=htonl(0x9df0003cu);
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,100)==200);
    assert(strcmp(out,"{\"results\":{\"static.whatsapp.net\":[\"157.240.0.60\"],\"web.whatsapp.com\":[\"157.240.0.60\"]}}")==0);
    public_dns=&fake_dns;srv_mode[0]=srv_mode[1]=srv_mode[2]=SRV_OK;
    resolver=system_resolve;clock_ms=monotonic_ms;public_dns=&fake_dns;
}

static void test_silent_resolvers(void) {
    char out[RESOLVE_REPLY_LIMIT];size_t used=0;
    const char *body="{\"hosts\":[\"static.whatsapp.net\",\"web.whatsapp.com\"]}";
    resolver=one_system;public_dns=&fake_dns;clock_ms=fake_clock;fake_silent_advances=1;
    sys_answer=htonl(0x3990f520u);
    /* One silent resolver: the phase stops at its wait limit, others count. */
    srv_mode[0]=SRV_SILENT;srv_mode[1]=SRV_OK;srv_first[1]=htonl(0x1f0d4834u);srv_count[1]=1;srv_mode[2]=SRV_SILENT;
    fake_ms=0;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,10)==200);
    assert(fake_ms>=PUBLIC_WAIT_MS&&fake_ms<=PUBLIC_WAIT_MS+250);
    assert(strstr(out,"\"static.whatsapp.net\":[\"57.144.245.32\",\"31.13.72.52\"]"));
    /* All silent and the deadline close: the public phase is skipped and the
       reply still comes before the deadline. */
    srv_mode[1]=SRV_SILENT;fake_ms=8500;fake_sent=0;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,10)==200);
    assert(fake_sent==0&&fake_ms==8500);
    fake_ms=0;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,10)==200);
    assert(fake_ms<=10000&&strstr(out,"\"web.whatsapp.com\":[\"57.144.245.32\"]"));
    srv_mode[0]=srv_mode[1]=srv_mode[2]=SRV_OK;fake_silent_advances=0;
    resolver=system_resolve;clock_ms=monotonic_ms;
}

static void test_http_boundaries(void) {
    char *big=malloc(4096);assert(big);
    const char *requests[]={
        "POST /register HTTP/1.1\r\nHost: relay\r\nContent-Length: 120\r\n\r\n",
        "GET /health HTTP/1.1\r\nHost: relay\r\n\r\n",
        "POST /ws HTTP/1.1\r\nContent-Length: 120\r\n\r\n",
        "POST /register HTTP/1.1\r\nContent-Length: 120\r\ncontent-length: 120\r\n\r\n",
        "POST /register HTTP/1.1\r\nContent-Length: 120\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /register HTTP/1.1\r\nContent-Length: 999999999999999999999\r\n\r\n",
        "POST /register HTTP/1.1\r\nHost: relay\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nHost: relay\r\nContent-Length: 2048\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: 2049\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: 40\r\ncontent-length: 40\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: 40\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: +40\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: 0040\r\n\r\n",
        "POST /resolve HTTP/1.1\r\nContent-Length: 40 \r\n\r\n",
        "POST /resolve HTTP/1.1\r\nHost: relay\r\n\r\n",
        "GET /resolve HTTP/1.1\r\n\r\n"
    };
    const int expected[]={200,204,404,400,400,400,400,200,400,400,400,400,400,400,400,400,400,404};
    const int routes[]={ROUTE_REGISTER,ROUTE_HEALTH,ROUTE_NONE,ROUTE_REGISTER,ROUTE_REGISTER,ROUTE_REGISTER,
        ROUTE_REGISTER,ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_RESOLVE,
        ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_RESOLVE,ROUTE_NONE};
    assert(sizeof(expected)==sizeof(routes)&&sizeof(requests)/sizeof(requests[0])==sizeof(expected)/sizeof(expected[0]));
    for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);i++){
        strcpy(big,requests[i]);size_t size=0;int route=-1;
        assert(parse_headers(big,&size,&route)==expected[i]);assert(route==routes[i]);
        if(expected[i]==200)assert(size==(route==ROUTE_REGISTER?120:2048));
    }
    strcpy(big,"POST /resolve HTTP/1.1\r\nContent-Length: 41\r\n\r\n");size_t size=0;int route=0;
    assert(parse_headers(big,&size,&route)==200&&size==41&&route==ROUTE_RESOLVE);
    free(big);
}

static void test_upstream_contract(void) {
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    assert(bind(listener,(struct sockaddr *)&addr,sizeof(addr))==0);assert(listen(listener,1)==0);
    socklen_t len=sizeof(addr);assert(getsockname(listener,(struct sockaddr *)&addr,&len)==0);
    pid_t child=fork();assert(child>=0);
    if(child==0){
        alarm(5);int fd=accept(listener,NULL,NULL);assert(fd>=0);char buf[2048]={0};size_t used=0;
        while(!strstr(buf,"\r\n\r\n")){assert(used<sizeof(buf)-1);assert(recv(fd,buf+used,1,0)==1);used++;}
        assert(strstr(buf,"POST /register HTTP/1.1\r\n"));assert(strstr(buf,"X-Forwarded-For: 192.0.2.1\r\n"));
        char *length=strstr(buf,"Content-Length: ");assert(length);size_t body_len=(size_t)atoi(length+16);
        assert(used+body_len<sizeof(buf));for(size_t i=0;i<body_len;i++)assert(recv(fd,buf+used+i,1,0)==1);
        char auth[65];assert(tg_register_hmac_hex("test-only",buf+used,body_len,auth)==0);
        assert(strstr(buf,auth));assert(!strstr(buf,"test-only"));
        const char response[]="HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nprivate-server-data";
        assert(socket_write_all(fd,response,sizeof(response)-1)==0);close(fd);close(listener);_exit(0);
    }
    uint8_t proof[PROOF_SIZE]={0};assert(forward_registration("test-only","192.0.2.1",proof,ntohs(addr.sin_port))==200);
    int status=0;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);close(listener);
}

int main(void){(void)signal(SIGPIPE,SIG_IGN);
    /* Unit tests never reach real DNS servers. */
    public_dns=&no_dns;
    test_proof();test_rate_limit();test_route_limits();test_http_boundaries();test_resolve();test_resolve_budget();test_dns_parse();test_dns_cname_chain();public_dns=&fake_dns;test_resolver_union();test_silent_resolvers();public_dns=&no_dns;test_lock_recovery();test_full_path();test_upstream_contract();puts("C enrollment server: proof, rate limits, HTTP boundaries, /resolve (budget, resolver union, DNS parsing, lock recovery, full TLS path) and upstream contract passed");return 0;}
