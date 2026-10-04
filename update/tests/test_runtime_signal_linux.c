#define _POSIX_C_SOURCE 200809L
#include "../../runtime/d2k_runtime.h"
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

static void pause_ms(void){struct timespec t={.tv_nsec=20000000L};nanosleep(&t,NULL);}
static int signal_masks(pid_t pid){
 char path[256];snprintf(path,sizeof path,"/proc/%ld/task",(long)pid);DIR *d=opendir(path);if(!d)return 0;
 unsigned workers=0;int good=1;unsigned long long needed=(UINT64_C(1)<<(SIGINT-1))|(UINT64_C(1)<<(SIGTERM-1));struct dirent *entry;
 while((entry=readdir(d))){char *end;long tid=strtol(entry->d_name,&end,10);if(tid<=0||*end)continue;
  snprintf(path,sizeof path,"/proc/%ld/task/%ld/status",(long)pid,tid);FILE *f=fopen(path,"r");if(!f){good=0;break;}
  char line[512];unsigned long long mask=0;int found=0;while(fgets(line,sizeof line,f))if(sscanf(line,"SigBlk: %llx",&mask)==1){found=1;break;}fclose(f);
  if(!found){good=0;break;}if(tid==(long)pid){if(mask&needed){fprintf(stderr,"main termination mask was not restored\n");good=0;}}
  else{workers++;if((mask&needed)!=needed){fprintf(stderr,"observer can receive SIGINT/SIGTERM\n");good=0;}}
 }
 closedir(d);return good&&workers>0;
}
static int long_reconnect_wait(pid_t pid,const char *log){
 FILE *f=fopen(log,"r");if(!f)return 0;char line[512];unsigned failures=0;
 while(fgets(line,sizeof line,f))if(strstr(line,"relay identity registration failed; will retry"))failures++;fclose(f);if(failures<3)return 0;
 char path[128];snprintf(path,sizeof path,"/proc/%ld/task/%ld/wchan",(long)pid,(long)pid);f=fopen(path,"r");if(!f)return 0;
 int asleep=fgets(line,sizeof line,f)&&strstr(line,"nanosleep");fclose(f);return asleep;
}
int main(int argc,char **argv){
 if(argc!=6||!argv[1][0]||!argv[2][0]||!argv[3][0]||!argv[4][0]||!argv[5][0]){fprintf(stderr,"usage: test_signal BINARY CONFIG HEALTH LOG STATUS\n");return 2;}
 unlink(argv[3]);pid_t pid=fork();if(pid<0)return 2;
 if(!pid){int log=open(argv[4],O_WRONLY|O_CREAT|O_TRUNC,0600);if(log<0)_exit(126);dup2(log,1);dup2(log,2);close(log);
  execl(argv[1],argv[1],"--config",argv[2],"--health-file",argv[3],(char *)NULL);_exit(127);}
 int result=1;uint64_t deadline=d2k_runtime_mono_ms()+5000;
 while(access(argv[3],F_OK)!=0&&d2k_runtime_mono_ms()<deadline)pause_ms();
 if(access(argv[3],F_OK)!=0){fprintf(stderr,"daemon health never started\n");goto cleanup;}
 if(!signal_masks(pid))goto cleanup;
 deadline=d2k_runtime_mono_ms()+20000;
 while(!long_reconnect_wait(pid,argv[4])&&d2k_runtime_mono_ms()<deadline)pause_ms();
 if(!long_reconnect_wait(pid,argv[4])){fprintf(stderr,"main did not enter >=7s reconnect sleep\n");goto cleanup;}
 uint64_t began=d2k_runtime_mono_ms();if(kill(pid,SIGTERM)!=0)goto cleanup;
 int status;pid_t ended;do{ended=waitpid(pid,&status,WNOHANG);if(ended==pid)break;pause_ms();}while(ended==0&&d2k_runtime_mono_ms()-began<1000);
 if(ended!=pid){fprintf(stderr,"SIGTERM did not interrupt main reconnect wait within 1000ms\n");goto cleanup;}
 pid=-1;if(!WIFEXITED(status)||WEXITSTATUS(status)!=0){fprintf(stderr,"daemon did not exit successfully\n");goto cleanup;}
 FILE *f=fopen(argv[5],"r");char state[32];if(!f)goto cleanup;int stopped=fgets(state,sizeof state,f)&&!strcmp(state,"stopped\n");fclose(f);if(!stopped)goto cleanup;
 printf("Linux observer signal mask + SIGTERM during long reconnect sleep: PASS (%llu ms)\n",(unsigned long long)(d2k_runtime_mono_ms()-began));result=0;
cleanup:
 if(pid>0){kill(pid,SIGKILL);while(waitpid(pid,NULL,0)<0&&errno==EINTR){}}
 return result;
}
