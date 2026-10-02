#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "d2k_quic_arms.h"
#include "profiles/quic_arms.h"

static const uint8_t default_blob[620]={0x40};
static const uint8_t zero_blob[16]={0};
static const char *names[]={"quic5","quic_google","quic_rutracker","fake_default_quic",
                           "0x00000000000000000000000000000000"};
const uint8_t *d2k_quic_original_blob(size_t index, size_t *len, const char **name) {
    static const uint8_t *const bytes[]={quic_donor_blob_0,quic_donor_blob_1,quic_donor_blob_2,default_blob,zero_blob};
    static const size_t sizes[]={sizeof quic_donor_blob_0,sizeof quic_donor_blob_1,sizeof quic_donor_blob_2,sizeof default_blob,sizeof zero_blob};
    if(index>=5 || !len) return NULL;
    *len=sizes[index]; if(name) *name=names[index]; return bytes[index];
}

/* Direct port of askArms.ask + addrPool.take. Never demand a second IP when
 * the already measured residual policy says to remain on the pinned address. */
static int ask(d2k_quic_arm_context *c, d2k_quic_arm *r, int blob, int copies,
               int ttl, int frag, int control, int *measured) {
    *measured=0;
    d2k_quic_arm_question q={0};
    q.copies=copies; q.ttl=ttl; q.frag=frag; q.control=control;
    const char *name="";
    if(blob>=0) q.blob=d2k_quic_original_blob((size_t)blob,&q.blob_len,&name);
    char label[192];
    static const char *frags[]={"", "ipfrag pos=8", "ipfrag pos=8 обратный порядок",
                               "z2k_ipfrag3_tiny", "z2k_ipfrag3"};
    if(control) snprintf(label,sizeof label,"фрагменты доходят вообще (контрольное имя)");
    else if(frag) snprintf(label,sizeof label,"фрагментация: %s",frags[frag]);
    else if(ttl) snprintf(label,sizeof label,"фальшивка %s с TTL %d",name,ttl);
    else if(copies>1) snprintf(label,sizeof label,"фальшивка %s ×%d",name,copies);
    else snprintf(label,sizeof label,"фальшивка %s",name);
    q.label=label;
    d2k_quic_arm_step *step=&r->trace[r->n_trace++]; /* max 18 questions */
    snprintf(step->label,sizeof step->label,"%s",label);
    if(c && c->can_ask && !c->can_ask(c->limit_user)) {
        r->incomplete=1; step->not_measured=2; return 0;
    }
    if(!c || !c->probe || !c->pool || !c->n_pool || (c->residual && c->next>=c->n_pool)) {
        r->incomplete=1; step->not_measured=1; return 0;
    }
    q.addr=c->pool[c->residual ? c->next++ : 0];
    snprintf(step->addr,sizeof step->addr,"%s",q.addr);
    int sent=0;
    d2k_tally t=c->probe(&q,c->user,&sent);
    step->sent=sent; step->answered=t.pass;
    if(sent>0) r->probes+=sent;
    if(!t.marked) c->marked=0;
    /* Unsent/local failures are not negative network observations. An
       ECONNREFUSED refusal (probe.go:643/663) is not err (quic_ask_ex counts
       it as fail): donor measure probe.go:573-574 keeps Refused out of
       NotBuilt, so askArms.ask
       (arms.go:69-94) treats the question as asked and not passed. */
    if(sent!=D2K_QUIC_REPEATS || t.err>0) { r->incomplete=1; step->not_measured=3; return 0; }
    *measured=1;
    if(t.pass!=D2K_QUIC_REPEATS) return 0;
    /* Fragment survival is a reachability control on a neutral name, not an
       arm; its answer is the original question. */
    if(control || !c->data) return 1;
    /* Task 39: the cheap filter passed; the arm counts only if real
       application data flows after a handshake with the same action. */
    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    d2k_quic_arm_data d=c->data(&q,c->data_user);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    if(c->spent) {
        int64_t ms=(int64_t)(t1.tv_sec-t0.tv_sec)*1000+(t1.tv_nsec-t0.tv_nsec)/1000000L;
        c->spent(c->limit_user,ms>0?(uint32_t)ms:0u);
    }
    step->data=(int)d.verdict; step->data_bytes=d.app_bytes;
    if(d.verdict==D2K_QAD_PASS) return 1;
    if(d.verdict==D2K_QAD_SHORT) { r->data_short++; r->incomplete=1; }
    else if(d.verdict==D2K_QAD_NOT_RUN) { r->incomplete=1; step->not_measured=3; *measured=0; }
    return 0;
}

d2k_quic_arm_data_verdict d2k_quic_arm_data_judge(int handshake, uint64_t app_bytes, int fin) {
    if(!handshake) return D2K_QAD_NO_HANDSHAKE;
    if(app_bytes>=D2K_QUIC_ARM_DATA_BYTES) return D2K_QAD_PASS;
    /* The server closed the response stream below the threshold: everything
       it had passed, so the line was not shown to cut it -- and not shown to
       carry the threshold either. Neither a pass nor a box failure. */
    return fin ? D2K_QAD_SHORT : D2K_QAD_CUT;
}

d2k_quic_arm d2k_quic_original_arms(d2k_quic_arm_context *c) {
    d2k_quic_arm r; memset(&r,0,sizeof r); r.kind=D2K_QA_NOT_FOUND; r.original=1;
    int chosen=-1, measured=0;
    /* 1. All original intrinsic fakes, in original order. */
    for(int b=0;b<5;b++) if(ask(c,&r,b,1,0,0,0,&measured)) { chosen=b; break; }
    /* 2. Either the successful fake, or quic5 then fake_default_quic. */
    int candidates[2]={chosen>=0?chosen:0,3};
    int nc=chosen>=0?1:2;
    const int repeats[]={6,11};
    for(int i=0;i<nc && !r.copies;i++) for(size_t j=0;j<2;j++) {
        if(ask(c,&r,candidates[i],repeats[j],0,0,0,&measured)) {
            chosen=candidates[i]; r.copies=repeats[j]; break;
        }
    }
    /* 3. Preferred successful fake, then quic5, then default (embedded,
       therefore all available). TTL is an independent original axis. */
    int decoy=chosen>=0?chosen:0;
    const int ttls[]={3,5,8,12};
    for(size_t i=0;i<4;i++) if(ask(c,&r,decoy,1,ttls[i],0,0,&measured)) {
        chosen=decoy; r.ttl=ttls[i]; break;
    }
    /* 4. Survival on control precedes every fragmentation arm. */
    int survived=ask(c,&r,-1,0,0,1,1,&measured);
    if(measured) {
        r.frag_survives=survived?D2K_PROP_YES:D2K_PROP_NO;
        if(survived) for(int shape=1;shape<=4;shape++) {
            if(ask(c,&r,-1,0,0,shape,0,&measured)) { r.frag_kind=shape; break; }
        }
    }
    if(chosen>=0) {
        const char *name="";
        const uint8_t *blob=d2k_quic_original_blob((size_t)chosen,&r.len,&name);
        memcpy(r.bytes,blob,r.len); snprintf(r.blob_name,sizeof r.blob_name,"%s",name);
        /* Original compose emits repeats=2 when no repeat axis succeeded. */
        if(!r.copies) r.copies=2;
        r.kind=r.ttl?D2K_QA_TTL:D2K_QA_COPIES;
    } else if(r.frag_kind) r.kind=D2K_QA_FRAG;
    if(c && !c->marked) r.kind=D2K_QA_FLAKY;
    snprintf(r.reason,sizeof r.reason,"original askArms: %s copies=%d ttl=%d frag=%d%s",
             chosen>=0?r.blob_name:"no fake",r.copies,r.ttl,r.frag_kind,
             r.incomplete?"; incomplete questions":"");
    if(r.data_short) {
        size_t used=strlen(r.reason);
        snprintf(r.reason+used,sizeof r.reason-used,
                 "; рукопожатие доказано, данные не измерены: ответ цели короче %u байт (%d)",
                 D2K_QUIC_ARM_DATA_BYTES,r.data_short);
    }
    return r;
}
