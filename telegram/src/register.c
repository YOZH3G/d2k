#define _POSIX_C_SOURCE 200809L
#include "tg_register.h"
#include "tg_tls.h"
#include "tg_identity.h"
#include "tg_net.h"
#include "tg_enroll.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

static int write_all(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off=0;
    while(off<len) { size_t n=0; if(SSL_write_ex(ssl,buf+off,len-off,&n)!=1 || !n)return -1; off+=n; }
    return 0;
}

static int read_response_headers(SSL *ssl, char *buf, size_t cap, int *status) {
    size_t used=0;
    while(used<cap-1) {
        size_t n=0;
        if(SSL_read_ex(ssl,buf+used,1,&n)!=1 || n!=1)return -1;
        ++used;
        if(used>=4 && memcmp(buf+used-4,"\r\n\r\n",4)==0)break;
    }
    if(used==cap-1)return -1;
    buf[used]='\0';
    int code=0;
    if(sscanf(buf,"HTTP/1.%*1[01] %3d",&code)!=1 || code<100 || code>599)return -1;
    *status=code;
    return 0;
}

int tg_enroll_identity(const char *hostname,uint16_t port,const char *ca_bundle,
                       const tg_identity *identity) {
    uint8_t proof[TG_ENROLL_SIZE];char request[768],response[16385];
    SSL_CTX *ctx=NULL;SSL *ssl=NULL;int fd=-1,status=0,result=-1;
    if(!hostname||strchr(hostname,'\r')||strchr(hostname,'\n')||!port||
       tg_enroll_proof(identity,proof)!=0)return -1;
    int n=snprintf(request,sizeof(request),
        "POST /register HTTP/1.1\r\nHost: %s:%u\r\nContent-Type: application/octet-stream\r\n"
        "Content-Length: %u\r\nConnection: close\r\n\r\n",hostname,(unsigned)port,TG_ENROLL_SIZE);
    if(n<=0||(size_t)n>=sizeof(request))return -1;
    fd=tg_tcp_connect_ipv4(hostname,port,10000);if(fd<0)goto done;
    ctx=tg_tls_client_context(ca_bundle);if(!ctx)goto done;
    ssl=tg_tls_connect_fd(ctx,fd,hostname);if(!ssl)goto done;
    if(write_all(ssl,(const uint8_t *)request,(size_t)n)!=0||write_all(ssl,proof,sizeof(proof))!=0||
       read_response_headers(ssl,response,sizeof(response),&status)!=0)goto done;
    result=status==200?0:status==409?TG_REGISTER_ID_CONFLICT:-1;
done:
    SSL_free(ssl);SSL_CTX_free(ctx);if(fd>=0)close(fd);return result;
}

int tg_register_identity(const char *hostname, uint16_t port,
                         const char *connect_ip, const char *ca_bundle,
                         const char *secret, const tg_identity *identity) {
    uint8_t pub[32];
    char pub64[45], body[256], auth[65], host_header[320], request[1024], response[16385];
    unsigned char *ssl64=(unsigned char *)pub64;
    int body_len, req_len, fd=-1, status=0, result=-1;
    SSL_CTX *ctx=NULL; SSL *ssl=NULL;
    if(!hostname || !*hostname || strchr(hostname,'\r') || strchr(hostname,'\n') ||
       !port || !secret || !*secret || !identity || !identity->private_key ||
       tg_identity_public_key(identity,pub)!=0) return -1;
    if(EVP_EncodeBlock(ssl64,pub,sizeof(pub))!=44)return -1;
    pub64[44]='\0';
    body_len=snprintf(body,sizeof(body),"{\"install_id\":\"%s\",\"pubkey\":\"%s\"}",
                      identity->install_id_hex,pub64);
    if(body_len<=0 || (size_t)body_len>=sizeof(body) ||
       tg_register_hmac_hex(secret,body,(size_t)body_len,auth)!=0)return -1;
    int host_len=snprintf(host_header,sizeof(host_header),"%s:%u",hostname,(unsigned)port);
    if(host_len<=0 || (size_t)host_len>=sizeof(host_header))return -1;
    req_len=snprintf(request,sizeof(request),
        "POST /register HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"
        "X-Z2K-Auth: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        host_header,auth,body_len,body);
    if(req_len<=0 || (size_t)req_len>=sizeof(request))return -1;
    fd=tg_tcp_connect_ipv4(connect_ip ? connect_ip : hostname,port,10000); if(fd<0)goto done;
    ctx=tg_tls_client_context(ca_bundle); if(!ctx)goto done;
    ssl=tg_tls_connect_fd(ctx,fd,hostname); if(!ssl)goto done;
    if(write_all(ssl,(const uint8_t *)request,(size_t)req_len)!=0 ||
       read_response_headers(ssl,response,sizeof(response),&status)!=0)goto done;
    result=status==200 ? 0 : status==409 ? TG_REGISTER_ID_CONFLICT : -1;
done:
    SSL_free(ssl); SSL_CTX_free(ctx); if(fd>=0)close(fd);
    OPENSSL_cleanse(auth,sizeof(auth));
    return result;
}
