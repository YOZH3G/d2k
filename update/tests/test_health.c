#define _POSIX_C_SOURCE 200809L
#include "d2k_update.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { uint64_t now; int fail_service, wrong_exe, wrong_release, mismatch, stale, unreadable, http_fail, rules_fail; int bad_ready; unsigned calls[4]; } fixture;
static d2ku_rc mono(void *p,uint64_t *v){*v=((fixture *)p)->now*1000000;return D2KU_OK;}
static d2ku_rc observe(void *p,unsigned service,const d2ku_journal *j,d2ku_health_observation *o){
 fixture *f=p;f->calls[service]++; memset(o,0,sizeof *o);o->pid=100+(int)service;o->start_ticks=42;
 o->executable_matches=!f->wrong_exe;strcpy(o->release_id,f->wrong_release?"other":j->new_release_id);strcpy(o->boot_id,"boot");
 o->heartbeat_mono_ms=f->stale?0:f->now;o->ready=f->bad_ready?2:1;o->wire=13;o->peer_connected=1;
 strcpy(o->peer_release_id,f->mismatch?"other":j->new_release_id);o->external_available=0;
 return f->fail_service?D2KU_HEALTH:D2KU_OK;
}
static d2ku_rc state(void *p){return ((fixture *)p)->unreadable?D2KU_IO:D2KU_OK;}
static d2ku_rc http(void *p){return ((fixture *)p)->http_fail?D2KU_HEALTH:D2KU_OK;}
static d2ku_rc rules(void *p){return ((fixture *)p)->rules_fail?D2KU_HEALTH:D2KU_OK;}
int main(void){
 fixture f={.now=1000};d2ku_ctx c={0};d2ku_journal j={0};d2ku_status s={0};
 c.clock.arg=&f;c.clock.monotonic=mono;c.health_arg=&f;c.health_observe=observe;c.health_state=state;c.health_http=http;c.health_rules=rules;c.wire_version=13;
 j.phase=D2KU_VALIDATING;j.active_services=D2KU_SERVICE_CORE|D2KU_SERVICE_DATAPATH|D2KU_SERVICE_PANEL;
 strcpy(j.transaction_id,"operation");j.transaction_id_len=9;strcpy(j.new_release_id,"release");j.new_release_id_len=7;
 strcpy(j.progress_boot_id,"boot");j.progress_boot_id_len=4;
 assert(d2ku_health(&c,&j,&s)==D2KU_OK&&!s.health_complete);
 for(f.now=2000;f.now<120000;f.now+=1000)assert(d2ku_health(&c,&j,&s)==D2KU_OK&&!s.health_complete);
 f.now=120999;assert(d2ku_health(&c,&j,&s)==D2KU_OK&&!s.health_complete);
 f.now=121000;assert(d2ku_health(&c,&j,&s)==D2KU_OK&&s.health_complete);
 /* A selected manifest change cannot inherit the previous validation window. */
 j.new_manifest_sha256[0]=1;
 assert(d2ku_health(&c,&j,&s)==D2KU_OK&&!s.health_complete);
 assert(f.calls[3]==0); /* disabled Telegram isn't probed */
 f.bad_ready=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.bad_ready=0;
 f.wrong_exe=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH&&!s.health_complete);f.wrong_exe=0;
 f.wrong_release=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.wrong_release=0;
 f.mismatch=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.mismatch=0;
 f.stale=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.stale=0;
 f.unreadable=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.unreadable=0;
 f.http_fail=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.http_fail=0;
 f.rules_fail=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.rules_fail=0;
 j.active_services|=D2KU_SERVICE_TELEGRAM;assert(d2ku_health(&c,&j,&s)==D2KU_OK&&!s.external_available);
 j.active_services=D2KU_SERVICE_TELEGRAM;f.rules_fail=1;assert(d2ku_health(&c,&j,&s)==D2KU_HEALTH);f.rules_fail=0;
 assert(d2ku_health(&c,&j,&s)==D2KU_OK);
 f.now--;assert(d2ku_health(&c,&j,&s)==D2KU_TIME&&!s.health_complete);
 c.health_observe=NULL;c.root_dirfd=-1;assert(d2ku_health(&c,&j,&s)!=D2KU_OK); /* defaults cannot pretend success */
 puts("health tests: PASS");return 0;
}
