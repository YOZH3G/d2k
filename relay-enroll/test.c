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
    strcat(all,"]}");assert(sizeof(resolve_hosts)/sizeof(resolve_hosts[0])==15);
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
static time_t fake_now;
static time_t fake_clock(void){return fake_now;}
static int slow_resolve(const char *host,uint32_t *out,size_t cap) {
    (void)host;fake_now+=3;if(!cap)return 0;out[0]=htonl(0x9df00001u);return 1;
}
static void test_resolve_budget(void) {
    resolver=slow_resolve;clock_now=fake_clock;fake_now=93;
    const char *body="{\"hosts\":[\"instagram.com\",\"www.instagram.com\",\"graph.instagram.com\"]}";
    char out[RESOLVE_REPLY_LIMIT];size_t used=0;
    assert(handle_resolve(body,strlen(body),out,sizeof(out),&used,100)==200);
    assert(strcmp(out,"{\"results\":{\"instagram.com\":[\"157.240.0.1\"],"
        "\"www.instagram.com\":[\"157.240.0.1\"],\"graph.instagram.com\":[]}}")==0);
    assert(fake_now==99);
    resolver=system_resolve;clock_now=monotonic_seconds;
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

int main(void){(void)signal(SIGPIPE,SIG_IGN);test_proof();test_rate_limit();test_route_limits();test_http_boundaries();test_resolve();test_resolve_budget();test_lock_recovery();test_full_path();test_upstream_contract();puts("C enrollment server: proof, rate limits, HTTP boundaries, /resolve (budget, lock recovery, full TLS path) and upstream contract passed");return 0;}
