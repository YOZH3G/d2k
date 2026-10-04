#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "d2k_update.h"
#include "../../runtime/d2k_runtime.h"
#include <assert.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

static d2ku_rc mono(void *arg,uint64_t *ns){(void)arg;*ns=d2k_runtime_mono_ms()*1000000;return D2KU_OK;}
static d2ku_rc good(void *arg){(void)arg;return D2KU_OK;}
static d2ku_rc observe(void *arg,unsigned which,const d2ku_journal *j,d2ku_health_observation *o){
 (void)arg;(void)which;memset(o,0,sizeof *o);o->pid=42;o->start_ticks=1;o->heartbeat_mono_ms=d2k_runtime_mono_ms();
 o->executable_matches=1;o->ready=1;o->wire=13;strcpy(o->release_id,j->new_release_id);strcpy(o->boot_id,j->progress_boot_id);return D2KU_OK;
}
/* Each probe owns a child and a separate 1s deadline: a FIFO hang never stops
 * the second regression or leaves a writer around to accidentally unblock it. */
static int bounded_probe(const char *name,d2ku_ctx *c,const d2ku_journal *j){
 int p[2];assert(pipe(p)==0);pid_t child=fork();assert(child>=0);
 if(!child){close(p[0]);d2ku_status status={.health_complete=1};d2ku_rc rc=d2ku_health(c,j,&status);
  unsigned char ok=rc==D2KU_HEALTH&&!status.health_complete;assert(write(p[1],&ok,1)==1);close(p[1]);_exit(0);}
 close(p[1]);struct pollfd ready={.fd=p[0],.events=POLLIN};int available=poll(&ready,1,1000);unsigned char ok=0;
 if(available>0)(void)read(p[0],&ok,1);if(!ok){fprintf(stderr,"%s: HEALTH/reset did not arrive within 1000ms\n",name);assert(kill(child,SIGKILL)==0);}
 close(p[0]);int status;assert(waitpid(child,&status,0)==child);if(ok)assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
 return ok?0:1;
}
int main(void){
 char root[]="/tmp/d2ku-fifo-XXXXXX";assert(mkdtemp(root));char path[512];
 d2ku_ctx c={0};c.root_dirfd=open(root,O_RDONLY|O_DIRECTORY);assert(c.root_dirfd>=0);c.health_runtime_dirfd=c.root_dirfd;
 c.clock.monotonic=mono;c.wire_version=13;c.health_rules=good;c.health_state=good;
 d2ku_journal j={.phase=D2KU_VALIDATING,.active_services=D2KU_SERVICE_DATAPATH};
 strcpy(j.transaction_id,"operation");j.transaction_id_len=9;strcpy(j.new_release_id,"dev");j.new_release_id_len=3;
 strcpy(j.progress_boot_id,"test-boot");j.progress_boot_id_len=9;
 snprintf(path,sizeof path,"%s/d2kd.health",root);assert(mkfifo(path,0600)==0);
 int failures=bounded_probe("health-record FIFO without writer",&c,&j);assert(unlink(path)==0);
 snprintf(path,sizeof path,"%s/state.fifo",root);assert(mkfifo(path,0600)==0);
 c.health_observe=observe;c.health_state=NULL;c.health_state_count=1;strcpy(c.health_state_paths[0],"state.fifo");j.active_services=D2KU_SERVICE_CORE;
 failures+=bounded_probe("state-path FIFO without writer",&c,&j);assert(unlink(path)==0);
 close(c.root_dirfd);assert(rmdir(root)==0);if(failures)return 1;puts("independent FIFO probe deadlines/reset: PASS");return 0;
}
