/* HTTP publication through the real controller process and d2kd control server.
 * Packet input/output is local; NFQUEUE and raw send remain a field boundary. */
#define main http_runtime_existing_main
#include "test_httpsearch.c"
#include "../datapath/include/d2k_session.h"
#include "../datapath/include/d2k_wire.h"
#include "../datapath/test_nat_stub.h"
#undef main
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"
#include "d2k_link.h"
#include "../datapath/test_runtime_trace.h"

static int live_diverge;
static d2k_result last_live_execution;
static int identity_peer, identity_delete_fail;
static const char live_host[]="portal-target.example";
static size_t live_packet(int family,uint16_t port,uint32_t seq,int syn,const char *request,uint8_t *pkt) {
    d2k_conn c={0};c.family=(uint8_t)family;c.ttl=61;c.window=32000;c.ack=76543;
    c.src_port=htons(port);c.dst_port=htons(80);c.ip_id=123;
    inet_pton(AF_INET,"192.0.2.1",&c.src_ip);inet_pton(AF_INET,"198.51.100.2",&c.dst_ip);
    inet_pton(AF_INET6,"2001:db8::1",c.src_ip6);inet_pton(AF_INET6,"2001:db8::2",c.dst_ip6);
    d2k_emit e={0};e.kind=D2K_EMIT_PAYLOAD;e.bytes=(const uint8_t *)request;e.len=strlen(request);e.seq=seq;
    size_t n=d2k_wire_build(&c,&e,pkt,4096),th=family==6?40:20;
    if(syn) {pkt[th+13]=2;unsigned sum=((unsigned)pkt[th+16]<<8|pkt[th+17])+0x16u;
        sum=(sum&65535u)+(sum>>16);pkt[th+16]=(uint8_t)(sum>>8);pkt[th+17]=(uint8_t)sum;}
    CHECK(n&&d2k_wire_tcp_checksum_ok(pkt,n),"live packet is valid");return n;
}
typedef struct { uint8_t bytes[6][4096]; d2k_test_packet packets[6]; size_t n; } live_trace;
static void live_flow(d2k_session *s,int family,uint16_t port,const char *host,int want,int probe,live_trace *trace) {
    uint8_t pkt[4096],out[65536];d2k_result r;
    size_t n=live_packet(family,port,10000,1,"",pkt);
    d2k_session_set_hook(s,D2K_HOOK_POSTROUTING);
    if(probe)d2k_session_packet_probe(s,pkt,n,1000000000,out,sizeof out,&r);
    else d2k_session_packet(s,pkt,n,1000000000,out,sizeof out,&r);
    char req[512];snprintf(req,sizeof req,"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: browser\r\n\r\n",host);
    uint32_t next_seq=10001;
    if(trace)trace->n=0;
    for(unsigned request=0;request<2;request++) {
    if(request)snprintf(req,sizeof req,"GET /False/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: browser\r\n\r\n",host);
    n=live_packet(family,port,next_seq,0,req,pkt);
    next_seq+=(uint32_t)strlen(req);
    if(probe)d2k_session_packet_probe(s,pkt,n,1100000000,out,sizeof out,&r);
    else d2k_session_packet(s,pkt,n,1100000000,out,sizeof out,&r);
    if(!want){CHECK(!r.applied&&!r.n_out,"unbound live host unchanged");return;}
    if(!r.applied)fprintf(stderr,"live HTTP skipped: %s\n",r.skipped?r.skipped:"none");
    CHECK(r.applied&&r.n_out==1,"permanent live HTTP emits exactly its checksum fake");
    CHECK(r.verdict==D2K_VERDICT_ACCEPT,"whole live request passes unchanged");
    if(r.n_out==1) {
        CHECK(!d2k_wire_tcp_checksum_ok(out+r.out[0].off,r.out[0].len),"actual fake has bad checksum");
        CHECK(d2k_wire_tcp_checksum_ok(pkt,n),"whole passed request checksum valid");
    }
    if(trace) {
        for(size_t i=0;i<r.n_out&&i<2;i++) {
            size_t at=trace->n++;
            memcpy(trace->bytes[at],out+r.out[i].off,r.out[i].len);
            trace->packets[at]=(d2k_test_packet){trace->bytes[at],r.out[i].len,r.out[i].delay_us};
        }
        if(r.verdict==D2K_VERDICT_ACCEPT) {
            size_t i=trace->n++;memcpy(trace->bytes[i],pkt,n);
            trace->packets[i]=(d2k_test_packet){trace->bytes[i],n,0};
        }
    }
    uint64_t done_before=d2k_session_done(s);
    CHECK(d2k_session_send_pending(s,&r.key,r.execution_id),"prepared output is not completed execution");
    for(size_t i=0;i<r.n_out+1;i++)d2k_session_sent(s,1200000000,&r.key,r.execution_id);
    CHECK(d2k_session_done(s)==done_before+1,"execution completes only after sends and verdict");
    last_live_execution=r;
    }
}
static void live_refusals(d2k_session *s,int family) {
    uint8_t pkt[4096],out[65536];d2k_result r;
    const char *req="GET / HTTP/1.1\r\nHost: portal-target.example\r\n\r\n";
    size_t n=live_packet(family,54000,10001,0,req,pkt);
    d2k_session_packet(s,pkt,n,2000000000,out,sizeof out,&r);
    CHECK(!r.applied&&r.skipped&&strstr(r.skipped,"HTTP: начало TCP"),"missing SYN has an explicit HTTP stream reason, not NO_PLAN");
    n=live_packet(family,54001,10000,1,"",pkt);
    d2k_session_packet(s,pkt,n,2000000001,out,sizeof out,&r);
    const char *part="GET / HTTP/1.1\r\nHost: portal-";
    n=live_packet(family,54001,10001,0,part,pkt);
    d2k_session_packet(s,pkt,n,2000000002,out,sizeof out,&r);
    CHECK(!r.applied&&r.skipped&&strstr(r.skipped,"HTTP: Host"),"split Host has an explicit parse reason, not NO_PLAN");
    n=live_packet(family,54001,10001,0,req,pkt);
    d2k_session_packet(s,pkt,n,2000000003,out,sizeof out,&r);
    CHECK(!r.applied&&r.skipped&&strstr(r.skipped,"HTTP: граница"),"lost request boundary has an explicit HTTP reason");
    /* A browser's large Cookie after a complete Host is a different case:
       matching does not require all headers to fit in one TCP segment. */
    char large[1301];const char *head="GET / HTTP/1.1\r\nHost: portal-target.example\r\nCookie: ";
    memset(large,'x',sizeof large-1);memcpy(large,head,strlen(head));large[sizeof large-1]=0;
    n=live_packet(family,54002,10000,1,"",pkt);d2k_session_packet(s,pkt,n,2000000004,out,sizeof out,&r);
    n=live_packet(family,54002,10001,0,large,pkt);d2k_session_packet(s,pkt,n,2000000005,out,sizeof out,&r);
    CHECK(r.applied&&r.n_out==1&&r.verdict==D2K_VERDICT_ACCEPT,"complete Host with partial large Cookie still applies measured whole-plan");
}
static int identity_set(void *ctx,const char *host,uint8_t family,const char *text,const uint8_t token[16]) {
    char hex[8192],err[200];
    (void)f_set_plan(ctx,host,family,text,token);
    if(d2k_plan_text_to_hex(text,hex,sizeof hex,err,sizeof err))return -1;
    return d2k_link_set_name_bound(identity_peer,host,6,hex,D2K_LINK_SHAPE_HTTP,family,token,err,sizeof err);
}
static int identity_del(void *ctx,const char *host,uint8_t family,const d2k_binding_context *binding) {
    char err[200];(void)family;((fake *)ctx)->del_plan_n++;
    return d2k_link_del_name_bound(identity_delete_fail ? -1 : identity_peer,host,6,binding,err,sizeof err);
}
static d2k_ev identity_ack(d2k_ctl *ctl,d2k_ctlsrv *cx,d2k_httpsearch *hs) {
    d2k_ev ev={0};char err[200];
    CHECK(d2k_ctl_poll(ctl,d2k_ctlsrv_command,cx)>0,"actual identity command consumed");
    d2k_ctl_flush(ctl);
    CHECK(!d2k_link_next(identity_peer,&ev,100,err,sizeof err)&&ev.kind==D2K_EV_ACK,"actual identity ACK decoded");
    (void)d2k_httpsearch_control(hs,&ev,10);
    return ev;
}
static int identity_portal(d2k_ctl *ctl,d2k_httpsearch *hs,const d2k_result *execution,int family,int variant) {
    d2k_http80_res portal={0};d2k_ev ev;char err[200];
    portal.family=(uint8_t)family;portal.client_port=53010;portal.server_port=80;
    snprintf(portal.host,sizeof portal.host,"%s",live_host);
    portal.execution_id=execution->execution_id;portal.binding=execution->binding;
    memcpy(portal.plan_id,execution->plan_id,16);
    struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);
    portal.request_ms=(uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000+100;
    /* Missing request path deliberately forbids starting any network probe. */
    if(variant==1)portal.binding.epoch[0]^=1;
    if(variant==2)memset(&portal.binding,0,sizeof portal.binding);
    if(variant==3)portal.trial_id[0]=1;
    d2k_ctlsrv_http80_event(ctl,&portal);d2k_ctl_flush(ctl);
    CHECK(!d2k_link_next(identity_peer,&ev,100,err,sizeof err)&&ev.kind==D2K_EV_HTTP_PORTAL,"production HTTP event encoder/decoder");
    CHECK(ev.live_execution==portal.execution_id &&
          !memcmp(ev.execution_binding.epoch,portal.binding.epoch,16),"request snapshot survives socket");
    return d2k_httpsearch_control(hs,&ev,(int64_t)portal.request_ms+1);
}
static void live_identity(d2k_ctl *ctl,d2k_ctlsrv *cx,int peer,int family,const char *store) {
    identity_peer=peer;d2k_ev drained;char err[200];
    d2k_ctl_flush(ctl);
    while(!d2k_link_next(peer,&drained,0,err,sizeof err)){}
    fake f={0};d2k_hs_ops ops=ops_of(&f);ops.set_plan=identity_set;ops.del_plan=identity_del;
    d2k_httpsearch *hs=d2k_httpsearch_new(&ops);size_t loaded=0;
    CHECK(!d2k_httpsearch_load(hs,store,&loaded,err,sizeof err)&&loaded==1,"identity restore fixture");
    d2k_ev first=identity_ack(ctl,cx,hs);
    CHECK(first.code==D2K_CMD_SET_NAME_BOUND && d2k_binding_known(&first.execution_binding) &&
          !memcmp(first.trial_id,f.install_id,16),"ACK belongs to this installation command");
    d2k_httpsearch_push_all(hs);
    /* SET is written but unconsumed: a new request still executes old binding. */
    live_flow(cx->sess,family,53010,live_host,1,0,NULL);
    d2k_result old=last_live_execution;
    CHECK(d2k_binding_equal(&old.binding,&first.execution_binding),"old flight fixture");
    d2k_ev second=identity_ack(ctl,cx,hs);
    CHECK(!d2k_binding_equal(&first.execution_binding,&second.execution_binding),"reinstall obtains different binding");
    CHECK(!identity_portal(ctl,hs,&old,family,0)&&!f.del_plan_n,"late old portal cannot revoke replacement");
    CHECK(!d2k_link_del_name_bound(peer,live_host,6,&old.binding,err,sizeof err),"stale conditional delete sent");
    (void)identity_ack(ctl,cx,hs);
    CHECK(d2k_plantab_find_http(d2k_session_plans(cx->sess),(const uint8_t *)live_host,strlen(live_host),(uint8_t)family,0,3)!=NULL,
          "datapath atomically preserves replacement from stale delete");
    live_flow(cx->sess,family,53011,live_host,1,0,NULL);
    d2k_result current=last_live_execution;
    CHECK(!identity_portal(ctl,hs,&current,family,1),"foreign table epoch cannot revoke");
    CHECK(!identity_portal(ctl,hs,&current,family,2),"unknown binding cannot revoke");
    CHECK(!identity_portal(ctl,hs,&current,family,3),"probe cannot revoke permanent binding");
    /* Deliver the event over the live link, then fail only the delete callback. */
    identity_delete_fail=1;
    CHECK(identity_portal(ctl,hs,&current,family,0)==1&&f.del_plan_n==1,"matching live portal revokes its owner");
    identity_delete_fail=0;
    d2k_httpsearch_push_all(hs);
    CHECK(f.del_plan_n==2,"resync retries exact failed revocation");
    (void)identity_ack(ctl,cx,hs);
    CHECK(!d2k_plantab_find_http(d2k_session_plans(cx->sess),(const uint8_t *)live_host,strlen(live_host),(uint8_t)family,0,4),"conditional live delete reaches actual table");
    CHECK(!identity_portal(ctl,hs,&current,family,0)&&f.del_plan_n==2,"duplicate portal cannot delete again");
    CHECK(!d2k_httpsearch_busy(hs),"missing replay context cannot launch network work");
    d2k_httpsearch_free(hs);
}

static void live_restore(int family) {
    char dir[128],path[180],sock[180],cat[180],log[180],err[300];
    snprintf(dir,sizeof dir,"/tmp/d2k-http-live-%ld-%d",(long)getpid(),family);
    CHECK(!mkdir(dir,0700),"private fixture directory");
    snprintf(path,sizeof path,"%s/http-plans.txt",dir);snprintf(sock,sizeof sock,"%s/s",dir);
    snprintf(cat,sizeof cat,"%s/catalog.json",dir);snprintf(log,sizeof log,"%s/controller.log",dir);
    fake f={0};d2k_hs_ops ops=ops_of(&f);d2k_httpsearch *hs=d2k_httpsearch_new(&ops);int64_t now=1;
    d2k_httpsearch_portal(hs,live_host,(uint8_t)family,IP,now);base_injected(hs,&f,&now);
    trial(hs,&f,&now,1,D2K_HS_SILENT);trial(hs,&f,&now,1,D2K_HS_REAL);trial(hs,&f,&now,1,D2K_HS_REAL);
    CHECK(f.set_plan_n==1&&strstr(f.last_plan,"proto tcp http"),"measured property confirms HTTP plan");
    CHECK(!d2k_httpsearch_save(hs,path,time(NULL),err,sizeof err),"actual measured HTTP store saved");
    d2k_httpsearch_free(hs);
    d2k_session *s=d2k_session_new(128,128);d2k_ctl *ctl=d2k_ctl_open(sock,err,sizeof err);
    CHECK(s&&ctl,"d2kd real control server opens");if(!s||!ctl)return;
    d2k_ctlsrv cx={.sess=s,.ctl=ctl,.now_ns=1};
    d2k_ctl_set_disconnect_hook(ctl,d2k_ctlsrv_peer_closed,&cx);
    pid_t child=fork();
    if(child==0){int fd=open(log,O_WRONLY|O_CREAT|O_TRUNC,0600);if(fd>=0){dup2(fd,1);dup2(fd,2);close(fd);}
        execl("./d2kc","d2kc","--control",sock,"--catalog",cat,(char *)NULL);_exit(127);}
    CHECK(child>0,"real d2kc starts");
    int greeted=0,installed=0;
    for(int i=0;i<250&&!installed;i++) {
        if(d2k_ctl_peer_fd(ctl)<0)d2k_ctl_accept(ctl);
        if(d2k_ctl_peer_fd(ctl)>=0&&!greeted){d2k_ctlsrv_greet(ctl,1500);greeted=1;}
        d2k_ctl_flush(ctl);d2k_ctl_poll(ctl,d2k_ctlsrv_command,&cx);
        installed=d2k_plantab_find_http(d2k_session_plans(s),(const uint8_t *)live_host,strlen(live_host),(uint8_t)family,0,2)!=NULL;
        if(!installed){struct timespec ts={0,20000000};nanosleep(&ts,NULL);}
    }
    CHECK(installed&&cx.bad_cmds==0,"d2kc reload reaches actual d2kd permanent table via Unix socket");
    live_flow(s,family,53001,live_host,1,0,NULL);live_flow(s,family,53002,"other.example",0,0,NULL);
    if(child>0){kill(child,SIGTERM);waitpid(child,NULL,0);}
    for(int i=0;i<20&&d2k_ctl_peer_fd(ctl)>=0;i++)d2k_ctl_poll(ctl,d2k_ctlsrv_command,&cx);
    int peer=d2k_link_open(sock,err,sizeof err);CHECK(peer>=0,"new measurement control connection");
    d2k_ctl_accept(ctl);
    char trial_hex[8192],permanent_hex[8192];const uint8_t tid[16]={9};
    CHECK(!d2k_plan_text_to_hex(f.last_probe_plan,trial_hex,sizeof trial_hex,err,sizeof err),"trial TLV");
    CHECK(!d2k_plan_text_to_hex(f.last_plan,permanent_hex,sizeof permanent_hex,err,sizeof err),"permanent TLV");
    CHECK(!d2k_link_set_name_probe_trial(peer,live_host,6,trial_hex,D2K_LINK_SHAPE_HTTP,htons(53003),(uint8_t)family,tid,err,sizeof err),"actual trial install command");
    CHECK(d2k_ctl_poll(ctl,d2k_ctlsrv_command,&cx)>0,"d2kd consumes trial install");
    live_trace measured={0},permanent={0};
    live_flow(s,family,53003,live_host,1,1,&measured);
    live_flow(s,family,53004,live_host,0,1,NULL);
    live_flow(s,family,53004,live_host,1,0,NULL);
    CHECK(!d2k_link_set_name_family(peer,live_host,6,permanent_hex,D2K_LINK_SHAPE_HTTP,0,(uint8_t)family,err,sizeof err),"permanent install before cleanup");
    CHECK(d2k_ctl_poll(ctl,d2k_ctlsrv_command,&cx)>0,"d2kd consumes permanent install");
    CHECK(!d2k_link_del_name_probe_family(peer,live_host,6,D2K_LINK_SHAPE_HTTP,htons(53003),(uint8_t)family,err,sizeof err),"exact trial cleanup command");
    CHECK(d2k_ctl_poll(ctl,d2k_ctlsrv_command,&cx)>0,"d2kd consumes cleanup");
    live_flow(s,family,53003,live_host,1,0,&permanent);
    if(live_diverge&&permanent.n)permanent.bytes[0][permanent.packets[0].len-1]^=1;
    CHECK(d2k_test_trace_equal(measured.packets,measured.n,permanent.packets,permanent.n),"actual control trial == restored/live permanent full packets");
    if(live_diverge&&permanent.n)permanent.bytes[0][permanent.packets[0].len-1]^=1;
    if(permanent.n){permanent.bytes[0][permanent.packets[0].len-1]^=1;
        CHECK(!d2k_test_trace_equal(measured.packets,measured.n,permanent.packets,permanent.n),"live gate rejects divergent packet");}
    live_refusals(s,family);
    live_identity(ctl,&cx,peer,family,path);
    d2k_link_close(peer);d2k_ctl_close(ctl);d2k_session_free(s);
    unlink(path);unlink(cat);unlink(log);unlink(sock);rmdir(dir);
}
int main(int argc,char **argv) {
    live_diverge=argc==2&&!strcmp(argv[1],"--diverge");
    D2K_TEST_NAT_NO_TABLE();
    live_restore(4);live_restore(6);
    printf("HTTP live controller/control/Session: IPv4/6 full packets + lifecycle, %d failures\n",fails);return fails?1:0;
}
