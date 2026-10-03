#include <stdio.h>
#include <string.h>
#include "d2k_quic_arms.h"
#include "d2k_quichello.h"
#include "d2k_quic.h"
static int calls, fails, lose_base_mark, junk16_asks;
static int fragment_calls;
static size_t first_prefix;
static uint8_t first_arm_hello[2048];
static size_t first_arm_hello_len;
static int arm_hello_count, arm_hello_changed;
#define CHECK(x) do { if(!(x)) { printf("FAIL %d %s\n",__LINE__,#x); fails++; } } while(0)
static size_t resolve(const char *sni,char out[][D2K_QUIC_ADDR_LEN],size_t cap) {
    (void)sni;(void)out;(void)cap;return 0;
}
static d2k_tally answer(int n,int *sent) {
    d2k_tally t={0}; t.marked=1; if(sent)*sent=n;
    if(lose_base_mark && calls==0)t.marked=0;
    if(calls++==1) t.fail=n; else t.pass=n;
    return t;
}
static d2k_tally ask(const char *ip,uint16_t port,const uint8_t *pre,size_t len,
    d2k_hello msg,uint32_t wait,uint32_t mark,int n,uint32_t *rtt,int *ref,int *sent,uint8_t *ttl) {
    (void)ip;(void)port;(void)wait;(void)mark;
    if(pre && !first_prefix) first_prefix=len;
    if(pre && len==16) junk16_asks++;
    if(pre) {
        uint8_t hello[2048]; size_t hello_len=0;
        CHECK(d2k_quic_client_hello(msg.bytes,msg.len,hello,sizeof hello,&hello_len)==0);
        if(arm_hello_count==0) {
            memcpy(first_arm_hello,hello,hello_len);
            first_arm_hello_len=hello_len;
        } else if(hello_len!=first_arm_hello_len ||
                  memcmp(hello,first_arm_hello,hello_len)!=0) {
            arm_hello_changed++;
        }
        arm_hello_count++;
    }
    if(rtt)*rtt=1;
    if(ref)*ref=0;
    if(ttl)*ttl=64;
    return answer(n,sent);
}
static d2k_tally copies(const char *ip,uint16_t port,const uint8_t *p,size_t l,int c,
    d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)c; return ask(ip,port,p,l,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally srcport(const char *ip,uint16_t port,int sp,d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)sp;return ask(ip,port,NULL,0,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally split(const char *ip,uint16_t port,d2k_hello h,const char *sni,uint32_t w,uint32_t m,int n,int *sent) {
    (void)sni;return ask(ip,port,NULL,0,h,w,m,n,NULL,NULL,sent,NULL);
}
static d2k_tally fragment(const char *ip,uint16_t port,int shape,d2k_hello h,uint32_t w,uint32_t m,int n,int *sent) {
    (void)ip;(void)port;(void)w;(void)m;
    char sni[256];
    CHECK(shape==1);
    CHECK(d2k_quic_sni(h.bytes,h.len,sni,sizeof sni)==0);
    CHECK(!strcmp(sni,fragment_calls%2==0?"z0123456789.example.com":"target.example"));
    fragment_calls++;
    d2k_tally t={0};t.pass=n;t.marked=1;*sent=n;return t;
}
/* Задача 40: вопросы стратегии (остаточное разрешение, разрез CRYPTO) идут
   раньше лестницы. 'U' — ответ не решающий (1/3 оба раза): лестница
   askArms остаётся запасным путём, и её порядок проверяется как прежде;
   'Y' — разрешение есть; 'N' — оба «нет». */
static char strategy_mode='U';
static int strategy_calls;
static d2k_tally arm_probe(const d2k_quic_arm_question *q,const char *sni,
    uint16_t port,uint32_t wait,uint32_t mark,int *sent) {
    uint8_t initial[1500];size_t initial_len=0;
    if(q->benign || q->split) {
        d2k_tally t={0};t.marked=1;*sent=D2K_QUIC_REPEATS;strategy_calls++;
        CHECK(sni && !strcmp(sni,"target.example"));
        if(strategy_mode=='U'){t.pass=1;t.fail=D2K_QUIC_REPEATS-1;}
        else if(strategy_mode=='Y' && q->benign) t.pass=D2K_QUIC_REPEATS;
        else t.fail=D2K_QUIC_REPEATS;
        return t;
    }
    /* Fragment survival names nothing: the wire layer draws a fresh donor
       neutralName() per repeat (arms.go:204-205), never the control
       snapshot's name or the scheduler decoy. */
    if(q->control) {
        CHECK(sni==NULL);
        sni="z0123456789.example.com";
    }
    if(!sni || d2k_quic_probe_initial(sni,initial,sizeof initial,&initial_len)!=0) {
        d2k_tally t={0};t.fail=t.err=D2K_QUIC_REPEATS;t.marked=(mark==0);*sent=0;return t;
    }
    d2k_hello msg={initial,initial_len};
    if(q->frag)return d2k_quic_fragment_hook(q->addr,port,q->frag,msg,wait,mark,D2K_QUIC_REPEATS,sent);
    if(q->ttl)return d2k_quic_ask_ttl_hook(q->addr,port,q->blob,q->blob_len,q->ttl,msg,wait,mark,D2K_QUIC_REPEATS,sent);
    if(q->copies>1)return d2k_quic_ask_copies_hook(q->addr,port,q->blob,q->blob_len,q->copies,msg,wait,mark,D2K_QUIC_REPEATS,sent);
    return d2k_quic_ask_hook(q->addr,port,q->blob,q->blob_len,msg,wait,mark,D2K_QUIC_REPEATS,NULL,NULL,sent,NULL);
}
/* Task 39: this test pins the ladder ORDER; the arm data stage (handshake
   plus application data) is stubbed as passed, and counted. */
static int data_calls;
static char want_path[64];
static d2k_quic_arm_data data_pass(const d2k_quic_arm_question *q,const char *sni,
    const char *path,uint16_t port,uint32_t wait,uint32_t mark) {
    (void)port;(void)wait;(void)mark;
    if(want_path[0]) CHECK(path && !strcmp(path,want_path));
    else CHECK(path==NULL); /* no known resource: the data stage asks "/" */
    CHECK(!q->control && sni && !strcmp(sni,"target.example"));
    data_calls++;
    d2k_quic_arm_data d; memset(&d,0,sizeof d);
    d.verdict=D2K_QAD_PASS; d.app_bytes=D2K_QUIC_ARM_DATA_BYTES;
    return d;
}
int main(void) {
    d2k_quic_arm_data_hook=data_pass;
    d2k_quic_allow_local=1; d2k_quic_resolve_hook=resolve;
    d2k_quic_ask_hook=ask; d2k_quic_ask_control_hook=ask;
    d2k_quic_ask_copies_hook=copies; d2k_quic_ask_ttl_hook=copies;
    d2k_quic_ask_srcport_hook=srcport; d2k_quic_ask_split_hook=split;
    d2k_quic_fragment_hook=fragment;
    d2k_quic_ask_arm_hook=arm_probe;
    uint8_t tb[1500],cb[1500];size_t tn=0,cn=0;
    CHECK(d2k_quic_probe_initial("target.example",tb,sizeof tb,&tn)==0);
    CHECK(d2k_quic_probe_initial("neutral.example",cb,sizeof cb,&cn)==0);
    d2k_quic_arm arm;
    memset(&arm,0,sizeof arm);
    d2k_vres r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE);
    CHECK(first_prefix==1200); /* quic5 before properties' 16-byte junk */
    CHECK(arm_hello_count>=2 && arm_hello_changed>0);
    CHECK(arm.original && arm.len==1200 && arm.ttl==3 && arm.copies==6);
    CHECK(fragment_calls==2 && arm.frag_kind==1 && arm.frag_survives==D2K_PROP_YES);
    CHECK(data_calls==4); /* quic5, copies 6, ttl 3, frag pos8; never the survival control */
    CHECK(strategy_calls==4 && arm.strategy==D2K_QS_LADDER); /* два вопроса, по одному повтору */
    /* Круг 1: заданное до предела повторов не задаётся снова — ни приманкой
       0x00…0 перебора, ни «мусором»/«кадрами» вопросника. */
    CHECK(junk16_asks==0 && arm.clearance_asked && arm.split_asked);
    CHECK(r.qtrace[0].sent==0 && r.qtrace[1].sent==0);
    CHECK(r.qprops.junk_ahead==D2K_PROP_UNKNOWN && r.qprops.split_crypto==D2K_PROP_UNKNOWN);
    CHECK(arm.n_trace>=4 && arm.trace[0].answered==1 && arm.trace[3].answered==1);
    /* The scheduler's known large resource reaches the data stage. */
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;
    memset(&arm,0,sizeof arm);
    snprintf(want_path,sizeof want_path,"/static/site.css");
    snprintf(arm.probe_path,sizeof arm.probe_path,"%s",want_path);
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},0,&arm);
    CHECK(data_calls==4 && !strcmp(arm.probe_path,want_path));
    /* Задача 40: остаточное разрешение есть — план из ответа, перебора нет,
       «мусор» вопросника второй раз не задаётся. */
    want_path[0]=0; memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;strategy_calls=0;strategy_mode='Y';
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},0,&arm);
    CHECK(r.verdict==D2K_V_OPAQUE && arm.kind==D2K_QA_BLOB && arm.strategy==D2K_QS_CLEARANCE);
    CHECK(arm.len==D2K_QUIC_BENIGN_LEN && arm.copies==1 && strategy_calls==1 && data_calls==1);
    CHECK(fragment_calls==0 && first_prefix==0);
    CHECK(r.qprops.junk_ahead==D2K_PROP_YES && r.qtrace[0].sent==0);
    /* Оба «нет»: обход не найден, приманки не перебираются. */
    memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;fragment_calls=0;data_calls=0;strategy_calls=0;strategy_mode='N';
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},0,&arm);
    /* Круг 1: приманки не перебираются, но вопросы фрагментации задаются;
       стенд пропускает фрагменты — план из ответа. */
    CHECK(arm.kind==D2K_QA_FRAG && arm.strategy==D2K_QS_FRAG && arm.frag_kind==1 &&
          arm.frag_survives==D2K_PROP_YES && !arm.incomplete);
    CHECK(strategy_calls==2 && data_calls==1 && fragment_calls==2 && first_prefix==0);
    CHECK(r.qprops.junk_ahead==D2K_PROP_NO && r.qprops.split_crypto==D2K_PROP_NO);
    CHECK(r.qtrace[0].sent==0 && r.qtrace[1].sent==0);
    strategy_mode='U';
    memset(&arm,0,sizeof arm);
    calls=0;first_prefix=0;lose_base_mark=1;
    r=d2k_quic_run("127.0.0.1",443,"target.example",
        (d2k_hello){tb,tn},(d2k_hello){cb,cn},99,&arm);
    CHECK(!r.marked && arm.kind==D2K_QA_FLAKY);
    if(fails)return 1;
    puts("original Run order: passed");return 0;
}
