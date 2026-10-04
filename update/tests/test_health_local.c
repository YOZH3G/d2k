#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "d2k_update.h"
#include "../../runtime/d2k_runtime.h"
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>

static d2ku_rc mono(void *arg,uint64_t *ns){(void)arg;*ns=d2k_runtime_mono_ms()*1000000;return D2KU_OK;}
static d2ku_rc good(void *arg){(void)arg;return D2KU_OK;}
static void write_file(const char *path,const char *value,mode_t mode){FILE *f=fopen(path,"w");assert(f);assert(fputs(value,f)>=0);assert(fclose(f)==0);assert(chmod(path,mode)==0);}
static pid_t http_server(uint16_t *port,int code){
 int fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);struct sockaddr_in a={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(0x7f000001)}};
 assert(bind(fd,(struct sockaddr *)&a,sizeof a)==0);socklen_t size=sizeof a;assert(getsockname(fd,(struct sockaddr *)&a,&size)==0);*port=ntohs(a.sin_port);assert(listen(fd,1)==0);
 pid_t p=fork();assert(p>=0);if(!p){alarm(5);int cli=accept(fd,NULL,NULL);if(cli>=0){char b[256];(void)read(cli,b,sizeof b);char response[64];int n=snprintf(response,sizeof response,"HTTP/1.1 %d local\r\nContent-Length: 0\r\n\r\n",code);(void)write(cli,response,(size_t)n);close(cli);}close(fd);_exit(0);}close(fd);return p;
}
static void wait_child(pid_t p){int status;assert(waitpid(p,&status,0)==p);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);}
#ifdef __linux__
static pid_t launch(const char *binary,const char *health){pid_t p=fork();assert(p>=0);if(!p){execl(binary,binary,"--helper",health,(char *)NULL);_exit(127);}return p;}
#endif
static d2ku_rc panel_observe(void *arg,unsigned service,const d2ku_journal *j,d2ku_health_observation *o){(void)arg;(void)service;memset(o,0,sizeof *o);o->pid=42;o->start_ticks=1;o->heartbeat_mono_ms=d2k_runtime_mono_ms();o->executable_matches=1;o->ready=1;o->wire=13;strcpy(o->release_id,j->new_release_id);strcpy(o->boot_id,j->progress_boot_id);return D2KU_OK;}
int main(int argc,char **argv){
 if(argc==3&&!strcmp(argv[1],"--helper")){for(;;){(void)d2k_runtime_heartbeat(argv[2],D2K_RELEASE_ID,1,1,0);struct timespec t={.tv_nsec=100000000L};nanosleep(&t,NULL);}}
 int not_listener=socket(AF_INET,SOCK_STREAM,0);assert(not_listener>=0);
 assert(d2k_runtime_listener_ready(not_listener)==0);
 struct sockaddr_in probe={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(0x7f000001)}};
 assert(bind(not_listener,(struct sockaddr *)&probe,sizeof probe)==0);assert(listen(not_listener,1)==0);
#ifdef __linux__
 assert(d2k_runtime_listener_ready(not_listener)==1);
#else
 /* Darwin exposes SO_ACCEPTCONN but returns ENOPROTOOPT; fail closed. */
 assert(d2k_runtime_listener_ready(not_listener)==0);
#endif
 close(not_listener);assert(d2k_runtime_listener_ready(not_listener)==0);
 char root[]="/tmp/d2ku-health-XXXXXX";assert(mkdtemp(root));char path[1024];snprintf(path,sizeof path,"%s/run",root);assert(mkdir(path,0700)==0);
 d2ku_ctx c={0};c.root_dirfd=open(root,O_RDONLY|O_DIRECTORY);c.health_runtime_dirfd=open(path,O_RDONLY|O_DIRECTORY);assert(c.root_dirfd>=0&&c.health_runtime_dirfd>=0);
 c.clock.monotonic=mono;c.wire_version=13;c.health_state=good;c.health_rules=good;
 d2ku_journal j={.phase=D2KU_VALIDATING};strcpy(j.transaction_id,"operation");j.transaction_id_len=9;strcpy(j.new_release_id,"dev");j.new_release_id_len=3;
 strcpy(j.progress_boot_id,"local");FILE *boot=fopen("/proc/sys/kernel/random/boot_id","r");if(boot){assert(fgets(j.progress_boot_id,sizeof j.progress_boot_id,boot));fclose(boot);j.progress_boot_id[strcspn(j.progress_boot_id,"\n")]=0;}j.progress_boot_id_len=strlen(j.progress_boot_id);
 d2ku_status s={0};c.health_observe=panel_observe;j.active_services=D2KU_SERVICE_PANEL;
 pid_t hp=http_server(&c.health_panel_port,200);assert(d2ku_health(&c,&j,&s)==D2KU_OK);wait_child(hp);
 hp=http_server(&c.health_panel_port,503);assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);wait_child(hp);
 c.health_http=good;c.health_state=NULL;c.health_state_count=1;strcpy(c.health_state_paths[0],"config");
 snprintf(path,sizeof path,"%s/config",root);write_file(path,"state is readable\n",0600);j.active_services=D2KU_SERVICE_TELEGRAM;
 assert(d2ku_health(&c,&j,&s)==D2KU_OK);assert(unlink(path)==0);assert(symlink("/etc/passwd",path)==0);assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);assert(unlink(path)==0);c.health_state=good;
#ifdef __linux__
 c.health_observe=NULL;const char *names[]={"d2kd","d2kc","d2kpanel","d2ktg"};pid_t children[4];
 snprintf(path,sizeof path,"%s/releases",root);assert(mkdir(path,0700)==0);snprintf(path,sizeof path,"%s/releases/dev",root);assert(mkdir(path,0700)==0);
 char exe[4096];ssize_t n=readlink("/proc/self/exe",exe,sizeof exe-1);assert(n>0);exe[n]=0;
 for(unsigned i=0;i<4;i++){char binary[1024],health[1024];snprintf(binary,sizeof binary,"%s/releases/dev/%s",root,names[i]);assert(link(exe,binary)==0);snprintf(health,sizeof health,"%s/run/%s.health",root,names[i]);children[i]=launch(binary,health);}
 j.active_services=15;int ready=0;for(unsigned tries=0;tries<30;tries++){if(d2ku_health(&c,&j,&s)==D2KU_OK){ready=1;break;}struct timespec t={.tv_nsec=100000000L};nanosleep(&t,NULL);}assert(ready&&!s.external_available);
 /* Running wrong executable with forged valid heartbeat cannot be healthy. */
 char bad[1024];snprintf(bad,sizeof bad,"%s/releases/dev/d2ktg",root);assert(unlink(bad)==0);write_file(bad,"different executable inode",0700);assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);
 c.health_rules=NULL;c.health_rule_count=4;c.health_queue=2000;
 const char *lines[]={"-A D2K_IN -j NFQUEUE --queue-num 2000 --queue-bypass","-A D2K_OUT -j NFQUEUE --queue-num 2000 --queue-bypass","-A FORWARD -j D2K_IN","-A OUTPUT -j D2K_OUT"};
 for(unsigned i=0;i<4;i++){strcpy(c.health_rule_lines[i],lines[i]);c.health_rule_family[i]=4;}
 char command[1024];snprintf(command,sizeof command,"%s/iptables-save",root);
 write_file(command,"#!/bin/sh\n[ \"$1\" = -t ] && [ \"$2\" = mangle ] || exit 1\nprintf '%s\\n' '-A D2K_IN -j NFQUEUE --queue-num 2000 --queue-bypass' '-A D2K_OUT -j NFQUEUE --queue-num 2000 --queue-bypass' '-A FORWARD -j D2K_IN' '-A OUTPUT -j D2K_OUT'\n",0700);
 assert(setenv("PATH",root,1)==0);j.active_services=1;assert(d2ku_health(&c,&j,&s)==D2KU_OK);
 c.health_queue=200;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);c.health_queue=2000;
 strcpy(c.health_rule_lines[0],"-A D2K_IN -p udp -j NFQUEUE --queue-num 2000 --queue-bypass");assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);
 for(unsigned i=0;i<4;i++){assert(kill(children[i],SIGTERM)==0);int status;assert(waitpid(children[i],&status,0)==children[i]);snprintf(path,sizeof path,"%s/releases/dev/%s",root,names[i]);unlink(path);snprintf(path,sizeof path,"%s/run/%s.health",root,names[i]);unlink(path);}
 unlink(command);snprintf(path,sizeof path,"%s/releases/dev",root);rmdir(path);snprintf(path,sizeof path,"%s/releases",root);rmdir(path);
 puts("Linux executable/heartbeat/own-rule probes: PASS");
#else
 puts("Linux executable/own-rule probes require Linux; portable HTTP/state probes: PASS");
#endif
 close(c.root_dirfd);close(c.health_runtime_dirfd);snprintf(path,sizeof path,"%s/run",root);assert(rmdir(path)==0);assert(rmdir(root)==0);
 return 0;
}
