#ifndef D2K_RUNTIME_H
#define D2K_RUNTIME_H
/* Shared build identity and volatile main-loop liveness. Offline CLI below
 * performs no file/network access. Release tooling supplies one RELEASE_ID. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#ifndef D2K_RELEASE_ID
#define D2K_RELEASE_ID "dev"
#endif
#define D2K_RUNTIME_WIRE 13u
static inline int d2k_runtime_id_valid(const char *id) {
    size_t n=strnlen(id,65); if(!n||n>64)return 0;
    for(size_t i=0;i<n;i++) { unsigned char c=(unsigned char)id[i];
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9'))continue;
        if(i&&(c=='.'||c=='_'||c=='-'))continue;
        return 0;
    }return 1;
}
static inline int d2k_runtime_offline(int argc,char **argv,const char *name,int (*self_check)(void)) {
    if(argc!=2)return -1;
    if(strcmp(argv[1],"--release-id")==0) { puts(D2K_RELEASE_ID);return d2k_runtime_id_valid(D2K_RELEASE_ID)?0:1; }
    if(strcmp(argv[1],"--self-check")==0) {
        if(!d2k_runtime_id_valid(D2K_RELEASE_ID)||!self_check||self_check()!=0)return 1;
        printf("%s self-check=ok release=%s wire=%u\n",name,D2K_RELEASE_ID,D2K_RUNTIME_WIRE);return 0;
    }return -1;
}
static inline uint64_t d2k_runtime_mono_ms(void) {
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)!=0)return 0;
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
static inline uint64_t d2k_runtime_start_ticks(const char *path) {
    char b[4096];FILE *f=fopen(path,"r");if(!f)return 0;
    char *ok=fgets(b,sizeof b,f);fclose(f);if(!ok)return 0;
    char *p=strrchr(b,')');if(!p)return 0;p++;
    for(unsigned field=3;field<=22;field++) { while(*p==' ')p++;char *end=p;while(*end&&*end!=' ')end++;
        if(field==22)return strtoull(p,NULL,10);
        if(!*end)return 0;
        p=end;
    }return 0;
}
/* Local installation readiness only: this does not establish relay/session
 * or tunnel application progress. A bound but non-listening fd is unhealthy. */
static inline int d2k_runtime_listener_ready(int fd) {
    int listening=0; socklen_t n=sizeof listening;
    return getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&listening,&n)==0&&listening!=0;
}
static inline int d2k_runtime_heartbeat(const char *path,const char *peer,int connected,int ready,int external) {
    static uint64_t last;uint64_t now=d2k_runtime_mono_ms();if(last&&now>=last&&now-last<1000)return 0;
    char boot[65]="local";FILE *bf=fopen("/proc/sys/kernel/random/boot_id","r");
    if(bf){if(!fgets(boot,sizeof boot,bf))strcpy(boot,"unknown");fclose(bf);boot[strcspn(boot,"\r\n")]=0;}
    char tmp[1024],body[512];int len=snprintf(body,sizeof body,"D2KH1 %ld %llu %llu %s %s %u %s %d %d %d\n",(long)getpid(),
        (unsigned long long)d2k_runtime_start_ticks("/proc/self/stat"),(unsigned long long)now,boot,D2K_RELEASE_ID,D2K_RUNTIME_WIRE,
        peer&&*peer?peer:"-",connected!=0,ready!=0,external!=0);
    if(!path||snprintf(tmp,sizeof tmp,"%s.tmp.%ld",path,(long)getpid())>=(int)sizeof tmp||len<0||len>=(int)sizeof body)return -1;
    int fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return -1;
    ssize_t n=write(fd,body,(size_t)len);int ok=n==len;if(close(fd)!=0)ok=0;
    if(!ok||rename(tmp,path)!=0){unlink(tmp);return -1;}last=now;return 0;
}
#endif
