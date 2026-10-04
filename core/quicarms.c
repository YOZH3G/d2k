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

const uint8_t d2k_quic_benign[D2K_QUIC_BENIGN_LEN] = {0};

/* Исход одного опроса: 1 прошло (фильтр 3/3 и этап данных), 0 не прошло.
   *measured — смысл askArms: все попытки ушли, и этап данных (если был)
   состоялся. *retry (может быть NULL) — исход НЕ решающий и спросить ещё
   раз есть на чём: не отправилось, повторы разошлись (1–2 из 3) или этап
   данных не состоялся. Решающий исход — measured без retry. */
/* Ход прогона (задача 49), см. d2k_quicprobe.h. */
d2k_quic_progress_fn d2k_quic_progress_hook = NULL;

static int ask_q(d2k_quic_arm_context *c, d2k_quic_arm *r, d2k_quic_arm_question *q,
                 const char *label, int *measured, int *retry) {
    *measured=0;
    if(retry) *retry=0;
    q->label=label;
    if(r->n_trace>=D2K_QUIC_ARM_STEPS) { r->incomplete=1; return 0; }
    d2k_quic_arm_step *step=&r->trace[r->n_trace++];
    snprintf(step->label,sizeof step->label,"%s",label);
    if(c && c->can_ask && !c->can_ask(c->limit_user)) {
        r->incomplete=1; step->not_measured=2; return 0;
    }
    if(!c || !c->probe || !c->pool || !c->n_pool || (c->residual && c->next>=c->n_pool)) {
        r->incomplete=1; step->not_measured=1; return 0;
    }
    q->addr=c->pool[c->residual ? c->next++ : 0];
    snprintf(step->addr,sizeof step->addr,"%s",q->addr);
    int sent=0;
    d2k_tally t=c->probe(q,c->user,&sent);
    step->sent=sent; step->answered=t.pass;
    if(sent>0) r->probes+=sent;
    if(sent>0 && d2k_quic_progress_hook) d2k_quic_progress_hook(label,sent); /* задача 49 */
    if(!t.marked) c->marked=0;
    /* Unsent/local failures are not negative network observations. An
       ECONNREFUSED refusal (probe.go:643/663) is not err (quic_ask_ex counts
       it as fail): donor measure probe.go:573-574 keeps Refused out of
       NotBuilt, so askArms.ask
       (arms.go:69-94) treats the question as asked and not passed. */
    if(sent!=D2K_QUIC_REPEATS || t.err>0) {
        r->incomplete=1; step->not_measured=3; if(retry) *retry=1; return 0;
    }
    *measured=1;
    if(t.pass!=D2K_QUIC_REPEATS) {
        /* 0/3 — решающее «нет»; 1–2 из 3 — повторы разошлись. */
        if(t.pass>0 && retry) *retry=1;
        return 0;
    }
    /* Fragment survival is a reachability control on a neutral name, not an
       arm; its answer is the original question. */
    if(q->control || !c->data) return 1;
    /* Task 39: the cheap filter passed; the arm counts only if real
       application data flows after a handshake with the same action. */
    struct timespec t0,t1;
    clock_gettime(CLOCK_MONOTONIC,&t0);
    q->need_complete=c->need_complete;
    d2k_quic_arm_data d=c->data(q,c->data_user);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    if(c->spent) {
        int64_t ms=(int64_t)(t1.tv_sec-t0.tv_sec)*1000+(t1.tv_nsec-t0.tv_nsec)/1000000L;
        c->spent(c->limit_user,ms>0?(uint32_t)ms:0u);
    }
    step->data=(int)d.verdict; step->data_bytes=d.app_bytes;
    snprintf(step->data_note,sizeof step->data_note,"%s",d.note);
    if(d.verdict==D2K_QAD_PASS) return 1;
    if(d.verdict==D2K_QAD_NOT_RUN) {
        r->incomplete=1; step->not_measured=3; *measured=0; if(retry) *retry=1;
    }
    return 0;
}

static int ask(d2k_quic_arm_context *c, d2k_quic_arm *r, int blob, int copies,
               int ttl, int frag, int control, int *measured);

/* Вопросы IP-фрагментации askArms: выживание на контроле, затем формы. Это
   вопросы замера, а не перебор приманок — их задаёт и стратегия, когда оба
   её ответа «нет» (задача 40, круг 1). */
static void ask_frag(d2k_quic_arm_context *c, d2k_quic_arm *r) {
    int measured=0;
    int survived=ask(c,r,-1,0,0,1,1,&measured);
    if(measured) {
        r->frag_survives=survived?D2K_PROP_YES:D2K_PROP_NO;
        if(survived) for(int shape=1;shape<=4;shape++) {
            if(ask(c,r,-1,0,0,shape,0,&measured)) { r->frag_kind=shape; break; }
        }
    }
}

/* Direct port of askArms.ask + addrPool.take. Never demand a second IP when
 * the already measured residual policy says to remain on the pinned address. */
static int ask(d2k_quic_arm_context *c, d2k_quic_arm *r, int blob, int copies,
               int ttl, int frag, int control, int *measured) {
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
    return ask_q(c,r,&q,label,measured,NULL);
}

d2k_quic_arm d2k_quic_original_arms(d2k_quic_arm_context *c) {
    d2k_quic_arm r; memset(&r,0,sizeof r); r.kind=D2K_QA_NOT_FOUND; r.original=1;
    int chosen=-1, measured=0;
    /* 1. All original intrinsic fakes, in original order. */
    for(int b=0;b<5;b++) {
        /* 0x00…0 ×1 — ровно вопрос «остаточное разрешение»; на него уже есть
           решающее «нет» (задача 40), второй раз он исхода не изменит. */
        if(b==4 && c && c->benign_answered) continue;
        if(ask(c,&r,b,1,0,0,0,&measured)) { chosen=b; break; }
    }
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
    ask_frag(c,&r);
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
    return r;
}

/* ---------------------------------------------------------------------
 * СТРАТЕГИЯ ИЗ ОТВЕТОВ (задача 40) — см. d2k_quic_arms.h.
 * --------------------------------------------------------------------- */

/* Один вопрос стратегии: до одного повтора, пока исход не решающий.
   Возвращает D2K_PROP_YES/NO или UNKNOWN (ответа нет). */
static int8_t strategy_ask(d2k_quic_arm_context *c, d2k_quic_arm *r,
                           const d2k_quic_arm_question *shape, const char *label,
                           int8_t *asked) {
    for(int attempt=0;attempt<2;attempt++) {
        d2k_quic_arm_question q=*shape;
        int measured=0, retry=0;
        int ok=ask_q(c,r,&q,label,&measured,&retry);
        /* Дошёл до провода (адрес и бюджет были) — вопрос задан. */
        if(r->n_trace && r->trace[r->n_trace-1].not_measured!=1 &&
           r->trace[r->n_trace-1].not_measured!=2) *asked=1;
        if(ok) return D2K_PROP_YES;
        if(measured && !retry) return D2K_PROP_NO;
        if(!retry) break; /* адрес или бюджет кончились — повтор не на чем */
    }
    return D2K_PROP_UNKNOWN;
}

static const char *prop_word(int8_t v) {
    return v==D2K_PROP_YES ? "прошло" : v==D2K_PROP_NO ? "не прошло" : "ответа нет";
}

d2k_quic_arm d2k_quic_strategy_arms(d2k_quic_arm_context *c) {
    d2k_quic_arm r; memset(&r,0,sizeof r);
    r.kind=D2K_QA_NOT_FOUND; r.original=1; r.strategy=D2K_QS_NONE;
    r.clearance=D2K_PROP_UNKNOWN; r.split_crypto=D2K_PROP_UNKNOWN;

    d2k_quic_arm_question benign={0};
    benign.blob=d2k_quic_benign; benign.blob_len=D2K_QUIC_BENIGN_LEN;
    benign.copies=1; benign.benign=1;
    r.clearance=strategy_ask(c,&r,&benign,
        "остаточное разрешение: безобидная датаграмма первой, затем Initial",
        &r.clearance_asked);
    if(r.clearance==D2K_PROP_YES) {
        memcpy(r.bytes,d2k_quic_benign,D2K_QUIC_BENIGN_LEN);
        r.len=D2K_QUIC_BENIGN_LEN;
        snprintf(r.blob_name,sizeof r.blob_name,"benign16");
        r.copies=1; r.kind=D2K_QA_BLOB; r.strategy=D2K_QS_CLEARANCE;
        r.incomplete=0; /* решающий ответ получен: прежний неустойчивый опрос — не пробел */
        snprintf(r.reason,sizeof r.reason,
                 "остаточное разрешение: одна безобидная датаграмма (%u нулевых байт) перед Initial",
                 (unsigned)D2K_QUIC_BENIGN_LEN);
    } else {
        d2k_quic_arm_question split={0};
        split.split=1;
        /* Финальное ревью core, I1: клиенту, чей ClientHello шире
           датаграммы, разрез CRYPTO не исполнится (датапат отказывает: имени
           нет в датаграмме). Ответ этого вопроса планом стать не может, и
           вопрос не задаётся; для выбора пути он считается «нет». */
        int no_split = c && c->no_split;
        if(!no_split)
            r.split_crypto=strategy_ask(c,&r,&split,"ClientHello двумя кадрами CRYPTO, хвост первым",
                                        &r.split_asked);
        if(r.split_crypto==D2K_PROP_YES) {
            r.kind=D2K_QA_SPLIT; r.strategy=D2K_QS_SPLIT; r.incomplete=0;
            snprintf(r.reason,sizeof r.reason,
                     "разрез ClientHello на два кадра CRYPTO проходит (остаточное разрешение: %s)",
                     prop_word(r.clearance));
        } else if(r.clearance==D2K_PROP_NO && (r.split_crypto==D2K_PROP_NO || no_split)) {
            /* Перебор приманок не нужен, но IP-фрагментация — отдельные
               вопросы замера (круг 1): задаются, и при ответе «да» план
               собирается из него. */
            r.incomplete=0;
            ask_frag(c,&r);
            if(r.frag_kind) {
                r.kind=D2K_QA_FRAG; r.strategy=D2K_QS_FRAG;
                snprintf(r.reason,sizeof r.reason,
                         "разрешение не прошло, разрез CRYPTO %s; IP-фрагментация формы %d прошла "
                         "(приманки не перебирались)",
                         no_split ? "клиенту неприменим (ClientHello шире датаграммы)" : "не прошёл",
                         r.frag_kind);
            } else {
                const char *fw = r.frag_survives==D2K_PROP_NO ? "фрагменты не доживают" :
                                 r.frag_survives==D2K_PROP_YES ? "ни одна форма" : "не измерена";
                if(no_split)
                    snprintf(r.reason,sizeof r.reason,
                             "обход по QUIC не найден: разрешение и фрагменты (%s) не прошли, "
                             "разрез CRYPTO клиенту неприменим; браузер уйдёт на TCP", fw);
                else
                    snprintf(r.reason,sizeof r.reason,
                             "обход по QUIC не найден: разрешение, разрез CRYPTO и фрагменты (%s) "
                             "не прошли; приманки не перебираются, браузер уйдёт на TCP", fw);
            }
        } else {
            /* Неизмеримо: запасной путь — перебор приманок оригинала. */
            int strategy_incomplete=r.incomplete;
            d2k_quic_arm_context local=*c;
            local.benign_answered=r.clearance_asked;
            d2k_quic_arm l=d2k_quic_original_arms(&local);
            c->next=local.next; c->marked=local.marked;
            size_t head=r.n_trace;
            int probes=r.probes;
            int8_t cl=r.clearance, sp=r.split_crypto;
            int8_t cla=r.clearance_asked, spa=r.split_asked;
            d2k_quic_arm_step steps[D2K_QUIC_ARM_STEPS];
            memcpy(steps,r.trace,head*sizeof steps[0]);
            r=l;
            size_t room=D2K_QUIC_ARM_STEPS-head;
            size_t take=l.n_trace<room?l.n_trace:room;
            memmove(r.trace+head,l.trace,take*sizeof r.trace[0]);
            memcpy(r.trace,steps,head*sizeof steps[0]);
            r.n_trace=head+take;
            r.probes+=probes;
            r.clearance=cl; r.split_crypto=sp;
            r.clearance_asked=cla; r.split_asked=spa;
            r.strategy=D2K_QS_LADDER;
            r.incomplete=r.incomplete||strategy_incomplete||take<l.n_trace;
            /* Причина перебора — его собственная строка, урезанная так,
               чтобы вместе с заголовком влезть в r.reason. */
            snprintf(r.reason,sizeof r.reason,
                     "ответа нет (разрешение: %s, разрез CRYPTO: %s) — запасной перебор: %.90s",
                     prop_word(cl),prop_word(sp),l.reason);
            return r;
        }
    }
    if(c && !c->marked) r.kind=D2K_QA_FLAKY;
    return r;
}
