#define _POSIX_C_SOURCE 200809L
#include "tg_listener.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

int tg_listener_decode_original_dst(const uint8_t *raw,size_t len,uint16_t *port,uint8_t ipv4[4]) {
    uint16_t family,network_port;
    if(!raw||!port||!ipv4||len<8)return -1;
    memcpy(&family,raw,sizeof(family));
    if(family!=AF_INET)return -1;
    memcpy(&network_port,raw+2,sizeof(network_port));*port=ntohs(network_port);
    memcpy(ipv4,raw+4,4);return *port?0:-1;
}

int tg_listener_is_self_dial(const uint8_t ip[4],uint16_t port,const uint16_t *ports,size_t count) {
    if(!ip)return 1;
    for(size_t i=0;i<count;i++)if(ports&&ports[i]==port)return 1;
    if(ip[0]==0 || ip[0]==10 || ip[0]==127 ||
       (ip[0]==169&&ip[1]==254) || (ip[0]==172&&ip[1]>=16&&ip[1]<=31) ||
       (ip[0]==192&&ip[1]==168))return 1;
    return 0;
}

int tg_listener_get_original_dst(int fd,uint16_t *port,uint8_t ipv4[4]) {
#if defined(__linux__)
    struct sockaddr_in addr; socklen_t len=sizeof(addr);
    memset(&addr,0,sizeof(addr));
    if(getsockopt(fd,SOL_IP,TG_SO_ORIGINAL_DST,&addr,&len)!=0)return -1;
    return tg_listener_decode_original_dst((const uint8_t *)&addr,len,port,ipv4);
#else
    (void)fd;(void)port;(void)ipv4;return -1;
#endif
}
