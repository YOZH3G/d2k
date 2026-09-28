/* Field acceptance only: send a fresh unencrypted req_pq_multi to a Telegram DC
   and require resPQ with the same nonce. No account or session secret is used. */
#define _POSIX_C_SOURCE 200809L
#include "tg_net.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int read_all(int fd,uint8_t *dst,size_t len) {
    while(len){ssize_t n=recv(fd,dst,len,0);if(n<=0)return -1;dst+=n;len-=(size_t)n;}return 0;
}

int main(int argc,char **argv) {
    const char *target=argc==2?argv[1]:"149.154.167.50";
    uint8_t request[42]={0xef,10},response[4096],nonce[16],head[4];
    uint64_t msgid=(uint64_t)time(NULL)<<32;
    for(size_t i=0;i<8;i++)request[10+i]=(uint8_t)(msgid>>(8*i));
    request[18]=20; /* message length */
    request[22]=0xf1;request[23]=0x8e;request[24]=0x7e;request[25]=0xbe;
    if(RAND_bytes(nonce,sizeof(nonce))!=1)return 1;
    memcpy(request+26,nonce,sizeof(nonce));
    int fd=tg_tcp_connect_ipv4(target,443,8000);if(fd<0){puts("DC connection failed");return 1;}
    if(send(fd,request,sizeof(request),0)!=(ssize_t)sizeof(request)||read_all(fd,head,1)!=0){puts("DC request/read failed");close(fd);return 1;}
    size_t words=head[0];
    if(words==127){if(read_all(fd,head,3)!=0){close(fd);return 1;}words=(size_t)head[0]|((size_t)head[1]<<8)|((size_t)head[2]<<16);}
    size_t size=words*4;
    if(size<40||size>sizeof(response)||read_all(fd,response,size)!=0){puts("invalid MTProto frame");close(fd);return 1;}
    close(fd);
    const uint8_t zero[8]={0},res_pq[4]={0x63,0x24,0x16,0x05};
    if(memcmp(response,zero,8)||memcmp(response+20,res_pq,4)||memcmp(response+24,nonce,16)){
        puts("MTProto response did not match req_pq_multi");return 1;
    }
    printf("MTProto resPQ verified from %s:443 (%zu bytes, nonce matched)\n",target,size);return 0;
}
