#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define main enrollment_program_main
#include "main.c"
#undef main
#include "tg_enroll.h"
#include <assert.h>

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
    for(int i=0;i<6;i++)assert(rate_allow(&limit,1,now));
    assert(!rate_allow(&limit,1,now));
    for(int i=6;i<120;i++)assert(rate_allow(&limit,(uint32_t)i,now));
    assert(!rate_allow(&limit,200,now));assert(rate_allow(&limit,1,now+60));
}

static void test_http_boundaries(void) {
    const char *requests[]={
        "POST /register HTTP/1.1\r\nHost: relay\r\nContent-Length: 120\r\n\r\n",
        "GET /health HTTP/1.1\r\nHost: relay\r\n\r\n",
        "POST /ws HTTP/1.1\r\nContent-Length: 120\r\n\r\n",
        "POST /register HTTP/1.1\r\nContent-Length: 120\r\ncontent-length: 120\r\n\r\n",
        "POST /register HTTP/1.1\r\nContent-Length: 120\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /register HTTP/1.1\r\nContent-Length: 999999999999999999999\r\n\r\n",
        "POST /register HTTP/1.1\r\nHost: relay\r\n\r\n"
    };
    const int expected[]={200,204,404,400,400,400,400};
    for(size_t i=0;i<sizeof(expected)/sizeof(expected[0]);i++){
        char headers[1024];strcpy(headers,requests[i]);size_t size=0;
        assert(parse_headers(headers,&size)==expected[i]);if(expected[i]==200)assert(size==120);
    }
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

int main(void){test_proof();test_rate_limit();test_http_boundaries();test_upstream_contract();puts("C enrollment server: proof, rate limits, HTTP boundaries and upstream contract passed");return 0;}
