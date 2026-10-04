#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "d2k_update.h"
#include "../../runtime/d2k_runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>

static const char *const binaries[4]={"d2kd","d2kc","d2kpanel","d2ktg"};
/* Walk through bounded trusted configuration paths; no symlink traversal. */
static int local_open(int root,const char *path,int directory) {
    if(root<0||!path||!*path||strnlen(path,D2KU_PATH_MAX+1)>D2KU_PATH_MAX)return -1;
    char b[D2KU_PATH_MAX+1];strcpy(b,path);int dir=dup(root);if(dir<0)return -1;
    char *p=b;
    for(;;){char *slash=strchr(p,'/');if(slash)*slash=0;
        if(!*p||!strcmp(p,".")||!strcmp(p,"..")){close(dir);return -1;}
        int flags=O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK;if(slash||directory)flags|=O_DIRECTORY;
        int fd=openat(dir,p,flags);close(dir);if(fd<0)return -1;
        if(!slash)return fd;
        dir=fd;p=slash+1;
    }
}
static d2ku_rc observe_local(d2ku_ctx *c,unsigned service,const d2ku_journal *j,d2ku_health_observation *o) {
    char path[256],b[512],extra;struct stat record,expected,actual;
    snprintf(path,sizeof path,"%s.health",binaries[service]);
    int fd=local_open(c->health_runtime_dirfd,path,0);if(fd<0)return D2KU_HEALTH;
    if(fstat(fd,&record)!=0||!S_ISREG(record.st_mode)||record.st_uid!=geteuid()||record.st_nlink!=1||(record.st_mode&077)!=0){close(fd);return D2KU_HEALTH;}
    ssize_t n=read(fd,b,sizeof b-1);close(fd);if(n<=0||n>=(ssize_t)sizeof b-1)return D2KU_HEALTH;b[n]=0;
    long pid;unsigned long long start,mono,wire;
    if(sscanf(b,"D2KH1 %ld %llu %llu %64s %64s %llu %64s %d %d %d %c",&pid,&start,&mono,o->boot_id,o->release_id,&wire,
        o->peer_release_id,&o->peer_connected,&o->ready,&o->external_available,&extra)!=10||pid<=1||pid>INT32_MAX)return D2KU_HEALTH;
    o->pid=(pid_t)pid;o->start_ticks=start;o->heartbeat_mono_ms=mono;o->wire=wire;
    if(!d2k_runtime_id_valid(o->release_id)||!start)return D2KU_HEALTH;
    snprintf(path,sizeof path,"releases/%s/%s",j->new_release_id,binaries[service]);
    fd=local_open(c->root_dirfd,path,0);if(fd<0)return D2KU_HEALTH;
    int rc=fstat(fd,&expected);close(fd);if(rc||!S_ISREG(expected.st_mode)||(expected.st_mode&0111)==0)return D2KU_HEALTH;
    snprintf(path,sizeof path,"/proc/%ld/exe",pid);
    if(stat(path,&actual)!=0||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino)return D2KU_HEALTH;
    snprintf(path,sizeof path,"/proc/%ld/stat",pid);
    if(d2k_runtime_start_ticks(path)!=start)return D2KU_HEALTH;
    o->executable_matches=1;return D2KU_OK;
}
static d2ku_rc readable_state(d2ku_ctx *c) {
    if(!c->health_state_count||c->health_state_count>8)return D2KU_HEALTH;
    for(size_t i=0;i<c->health_state_count;i++){
        int fd=local_open(c->root_dirfd,c->health_state_paths[i],0);if(fd<0)return D2KU_HEALTH;
        struct stat st;char b[4096];
        if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)){close(fd);return D2KU_HEALTH;}
        ssize_t n;do{n=read(fd,b,sizeof b);}while(n>0);close(fd);if(n<0)return D2KU_HEALTH;
    }return D2KU_OK;
}
static d2ku_rc local_http(d2ku_ctx *c) {
    int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return D2KU_HEALTH;
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(c->health_panel_port?c->health_panel_port:8090),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    int send_flags=0;
#ifdef MSG_NOSIGNAL
    send_flags=MSG_NOSIGNAL;
#elif defined(SO_NOSIGPIPE)
    int suppress=1;(void)setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&suppress,sizeof suppress);
#endif
    int flags=fcntl(fd,F_GETFL);int ok=flags>=0&&fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0;
    if(ok&&connect(fd,(struct sockaddr *)&a,sizeof a)!=0&&errno!=EINPROGRESS)ok=0;
    struct pollfd p={.fd=fd,.events=POLLOUT};int err=0;socklen_t len=sizeof err;
    if(ok&&(poll(&p,1,1000)!=1||getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&len)!=0||err))ok=0;
    const char request[]="GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if(ok&&send(fd,request,sizeof request-1,send_flags)!=(ssize_t)sizeof request-1)ok=0;
    char response[64]={0};size_t used=0;uint64_t began=d2k_runtime_mono_ms();p.events=POLLIN;
    while(ok&&used<sizeof response-1&&!strchr(response,'\n')){
        if(d2k_runtime_mono_ms()-began>=1000||poll(&p,1,100)!=1){if(d2k_runtime_mono_ms()-began>=1000)ok=0;continue;}
        ssize_t n=recv(fd,response+used,sizeof response-1-used,0);if(n<=0){ok=0;break;}used+=(size_t)n;response[used]=0;
    }
    close(fd);return ok&&(!strncmp(response,"HTTP/1.1 200 ",13)||!strncmp(response,"HTTP/1.0 200 ",13))?D2KU_OK:D2KU_HEALTH;
}
static int rule_token(const char *line,const char *token) {
    const char *p=strstr(line,token);if(!p)return 0;
    char end=p[strlen(token)];return end==0||end==' '||end=='\t';
}
/* Read-only command, fixed argv; never run shell or expose firewall output. */
static d2ku_rc own_rules(d2ku_ctx *c,const char *program,unsigned family) {
    if (!c->health_rule_count || c->health_rule_count > 32) return D2KU_HEALTH;
    int pipes[2];if(pipe(pipes))return D2KU_HEALTH;
    pid_t pid=fork();if(pid<0){close(pipes[0]);close(pipes[1]);return D2KU_HEALTH;}
    if(pid==0){close(pipes[0]);dup2(pipes[1],STDOUT_FILENO);close(pipes[1]);int null=open("/dev/null",O_WRONLY);if(null>=0){dup2(null,STDERR_FILENO);close(null);}execlp(program,program,"-t","mangle",(char *)NULL);_exit(127);}
    close(pipes[1]);char output[65536];size_t used=0;int ok=1;uint64_t began=d2k_runtime_mono_ms();
    struct pollfd p={.fd=pipes[0],.events=POLLIN};
    for(;;){if(d2k_runtime_mono_ms()-began>=2000||used>=sizeof output-1){ok=0;break;}
        int ready=poll(&p,1,100);if(ready<0){if(errno==EINTR)continue;ok=0;break;}if(!ready)continue;
        ssize_t n=read(pipes[0],output+used,sizeof output-1-used);if(n==0)break;if(n<0){if(errno==EINTR)continue;ok=0;break;}used+=(size_t)n;
    }
    close(pipes[0]);if(!ok)kill(pid,SIGKILL);int status;while(waitpid(pid,&status,0)<0){if(errno!=EINTR)return D2KU_HEALTH;}
    if(!ok||!WIFEXITED(status)||WEXITSTATUS(status))return D2KU_HEALTH;
    output[used]=0;char queue[48];snprintf(queue,sizeof queue,"--queue-num %u",c->health_queue);
    int in=0,out=0,jumpin=0,jumpout=0; unsigned char found[32]={0}; size_t required=0;
    for(size_t i=0;i<c->health_rule_count;i++)if(c->health_rule_family[i]==family)required++;
    if(!required)return D2KU_HEALTH;
    for(char *line=output;line&&*line;){char *next=strchr(line,'\n');if(next)*next++=0;
        if(!strncmp(line,"-A D2K_IN ",10)&&strstr(line,"-j NFQUEUE ")&&rule_token(line,queue))in=1;
        if(!strncmp(line,"-A D2K_OUT ",11)&&strstr(line,"-j NFQUEUE ")&&rule_token(line,queue))out=1;
        if(!strncmp(line,"-A FORWARD ",11)&&rule_token(line,"-j D2K_IN"))jumpin=1;
        if(!strncmp(line,"-A OUTPUT ",10)&&rule_token(line,"-j D2K_OUT"))jumpout=1;
        for(size_t i=0;i<c->health_rule_count;i++)if(c->health_rule_family[i]==family&&!strcmp(line,c->health_rule_lines[i]))found[i]=1;
        line=next;
    }
    for(size_t i=0;i<c->health_rule_count;i++)if(c->health_rule_family[i]==family&&!found[i])return D2KU_HEALTH;
    return in&&out&&jumpin&&jumpout?D2KU_OK:D2KU_HEALTH;
}
static d2ku_rc fail(d2ku_status *s,d2ku_rc rc){s->health_observing=0;s->installation_healthy=0;s->health_complete=0;return rc;}
d2ku_rc d2ku_health(d2ku_ctx *c,const d2ku_journal *j,d2ku_status *s) {
    if(!c||!j||!s||!c->clock.monotonic)return D2KU_INVALID;
    if(!memchr(j->progress_boot_id,0,sizeof j->progress_boot_id) ||
        j->new_release_id_len != strnlen(j->new_release_id,sizeof j->new_release_id) ||
        j->transaction_id_len != strnlen(j->transaction_id,sizeof j->transaction_id) ||
        j->progress_boot_id_len != strlen(j->progress_boot_id) || j->phase!=D2KU_VALIDATING||j->active_services&~UINT64_C(15)||!d2k_runtime_id_valid(j->new_release_id)||
        !d2k_runtime_id_valid(j->transaction_id)||!j->progress_boot_id[0])return fail(s,D2KU_INVALID);
    uint64_t ns;if(c->clock.monotonic(c->clock.arg,&ns)!=D2KU_OK)return fail(s,D2KU_TIME);uint64_t now=ns/1000000;
    if(s->health_observing&&now<s->health_last_ms)return fail(s,D2KU_TIME);
    int reset=!s->health_observing||strcmp(s->health_transaction,j->transaction_id)||strcmp(s->health_boot,j->progress_boot_id)||
        strcmp(s->health_release,j->new_release_id)||memcmp(s->health_manifest_sha256,j->new_manifest_sha256,32)||s->health_services!=j->active_services||now-s->health_last_ms>D2KU_HEARTBEAT_MS;
    d2ku_health_observation observations[4];memset(observations,0,sizeof observations);s->external_available=1;
    for(unsigned i=0;i<4;i++)if(j->active_services&(UINT64_C(1)<<i)){
        d2ku_health_observation *o=&observations[i];
        d2ku_rc rc=c->health_observe?c->health_observe(c->health_arg,i,j,o):observe_local(c,i,j,o);
        uint64_t current_ns;
        if(c->clock.monotonic(c->clock.arg,&current_ns)!=D2KU_OK||current_ns/1000000<now)return fail(s,D2KU_TIME);
        now=current_ns/1000000;
        if(!memchr(o->release_id,0,sizeof o->release_id)||!memchr(o->peer_release_id,0,sizeof o->peer_release_id)||!memchr(o->boot_id,0,sizeof o->boot_id))return fail(s,D2KU_HEALTH);
        uint64_t freshness=D2KU_HEARTBEAT_MS;
        if(rc!=D2KU_OK||o->pid<=1||!o->start_ticks||o->executable_matches!=1||o->ready!=1||strcmp(o->release_id,j->new_release_id)||
            strcmp(o->boot_id,j->progress_boot_id)||o->wire!=c->wire_version||o->heartbeat_mono_ms>now||now-o->heartbeat_mono_ms>freshness)return fail(s,D2KU_HEALTH);
        if(i==0&&(j->active_services&D2KU_SERVICE_CORE)&&o->peer_connected!=1)return fail(s,D2KU_HEALTH);
        if(i==1&&(j->active_services&D2KU_SERVICE_DATAPATH)&&(o->peer_connected!=1||strcmp(o->peer_release_id,j->new_release_id)))return fail(s,D2KU_HEALTH);
        if(s->health_pid[i]!=o->pid||s->health_start_ticks[i]!=o->start_ticks)reset=1;
        if(i==3)s->external_available=o->external_available;
    }
    if((j->active_services&(D2KU_SERVICE_CORE|D2KU_SERVICE_TELEGRAM))&&(c->health_state?c->health_state(c->health_arg):readable_state(c))!=D2KU_OK)return fail(s,D2KU_HEALTH);
    if((j->active_services&D2KU_SERVICE_PANEL)&&(c->health_http?c->health_http(c->health_arg):local_http(c))!=D2KU_OK)return fail(s,D2KU_HEALTH);
    if(j->active_services&(D2KU_SERVICE_DATAPATH|D2KU_SERVICE_TELEGRAM)){
        /* Telegram rule ownership depends on configured NAT/ipsets/filter.
         * Its service adapter must probe these; no generic success default. */
        if((j->active_services&D2KU_SERVICE_TELEGRAM)&&!c->health_rules)return fail(s,D2KU_HEALTH);
        d2ku_rc rc=c->health_rules?c->health_rules(c->health_arg):own_rules(c,"iptables-save",4);
        if(rc!=D2KU_OK)return fail(s,D2KU_HEALTH);
        if(!c->health_rules&&c->health_ipv6_rules&&own_rules(c,"ip6tables-save",6)!=D2KU_OK)return fail(s,D2KU_HEALTH);
    }
    if(reset)s->health_since_ms=now;
    for(unsigned i=0;i<4;i++){s->health_pid[i]=observations[i].pid;s->health_start_ticks[i]=observations[i].start_ticks;}
    strcpy(s->health_transaction,j->transaction_id);strcpy(s->health_boot,j->progress_boot_id);s->health_services=j->active_services;
    strcpy(s->health_release,j->new_release_id);memcpy(s->health_manifest_sha256,j->new_manifest_sha256,32);
    s->health_last_ms=now;s->health_observing=1;s->installation_healthy=1;s->health_complete=now-s->health_since_ms>=D2KU_VALIDATION_MS;
    return D2KU_OK;
}
