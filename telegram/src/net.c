#define _POSIX_C_SOURCE 200809L
#include "tg_net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int tg_nip_host_to_ipv4(const char *hostname, char out[16]) {
    char host[256], canonical[16];
    size_t len;
    unsigned octets[4];
    if (!hostname || !out || (len=strlen(hostname)) >= sizeof(host)) return 0;
    memcpy(host,hostname,len+1);
    if(len && host[len-1]=='.')host[--len]='\0';
    static const char suffix[]=".nip.io";
    if(len<=sizeof(suffix)-1 || strcmp(host+len-(sizeof(suffix)-1),suffix)!=0)return 0;
    host[len-(sizeof(suffix)-1)]='\0';
    char *p=host;
    for(size_t i=0;i<4;i++) {
        char *end; unsigned long value;
        if(!*p)return 0;
        for(const char *digit=p;*digit && *digit!='.';digit++)
            if(*digit<'0' || *digit>'9')return 0;
        errno=0; value=strtoul(p,&end,10);
        if(errno || end==p || value>255 || (end-p)>3 || (end-p>1 && *p=='0'))return 0;
        octets[i]=(unsigned)value;
        if(i<3) { if(*end!='.')return 0; p=end+1; }
        else if(*end!='\0')return 0;
    }
    int n=snprintf(canonical,sizeof(canonical),"%u.%u.%u.%u",octets[0],octets[1],octets[2],octets[3]);
    if(n<=0 || (size_t)n>=sizeof(canonical))return 0;
    strcpy(out,canonical); return 1;
}

int tg_tcp_connect_ipv4(const char *hostname, uint16_t port, unsigned timeout_ms) {
    char extracted[16];
    const char *lookup=hostname;
    struct addrinfo hints={0},*list=NULL,*ai;
    char service[8]; int fd=-1;
    if(!hostname || !*hostname || !port)return -1;
    if(tg_nip_host_to_ipv4(hostname,extracted)==1)lookup=extracted;
    snprintf(service,sizeof(service),"%u",(unsigned)port);
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM; hints.ai_protocol=IPPROTO_TCP;
    if(getaddrinfo(lookup,service,&hints,&list)!=0)return -1;
    for(ai=list;ai;ai=ai->ai_next) {
        int flags,rc,error=0; socklen_t error_len=sizeof(error);
        fd=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol); if(fd<0)continue;
        flags=fcntl(fd,F_GETFL,0);
        if(flags<0 || fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0) { close(fd); fd=-1; continue; }
        rc=connect(fd,ai->ai_addr,ai->ai_addrlen);
        if(rc<0 && errno==EINPROGRESS) {
            struct pollfd pfd={.fd=fd,.events=POLLOUT};
            do { rc=poll(&pfd,1,(int)timeout_ms); } while(rc<0 && errno==EINTR);
            if(rc>0 && getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&error_len)==0 && error==0)rc=0;
            else rc=-1;
        }
        if(rc==0 && fcntl(fd,F_SETFL,flags)==0) {
            struct timeval tv={.tv_sec=(time_t)(timeout_ms/1000),.tv_usec=(suseconds_t)((timeout_ms%1000)*1000)};
            (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
            (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
            break;
        }
        close(fd); fd=-1;
    }
    freeaddrinfo(list); return fd;
}
