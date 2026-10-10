/* One UDP hypothesis compiler, used by measurement and stored plans. */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "d2k_compose.h"
#include "d2k_quic_arms.h"
#include "d2k_quicprobe.h"
#include "d2k_voice.h"

static int append_fmt(char *buf, size_t cap, size_t *pos, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *pos) {
        return -1;
    }
    *pos += (size_t)n;
    return 0;
}

/* Общая шапка любого плана этого файла: во всех шести Schema=1, MinExec=1
 * (plan.SchemaCurrent, properties.go), а plan.ID у Go-стороны здесь везде
 * нулевой — ни один из шести конструкторов (overlapPlan..everythingPlan) не
 * заполняет поле ID, каталожный идентификатор ("plan-XXXXXXXX") считается
 * ПОЗЖЕ и ОТДЕЛЬНО хэшем текста (planID(text) в properties.go), а не хранится
 * в самом тексте плана. */
static int emit_header_proto(char *buf, size_t cap, size_t *pos, const char *proto) {
    static const char zero32[] = "00000000000000000000000000000000000000";
    if (append_fmt(buf, cap, pos, "d2k-plan 1 1\n") != 0) { return -1; }
    if (append_fmt(buf, cap, pos, "id %.32s\n", zero32) != 0) { return -1; }
    if (append_fmt(buf, cap, pos, "proto %s\n", proto) != 0) { return -1; }
    return 0;
}

static int append_hex(char *buf, size_t cap, size_t *pos,
                       const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (append_fmt(buf, cap, pos, "%02x", b[i]) != 0) { return -1; }
    }
    return 0;
}

/* Exactly the independent questions. Combining positive answers requires
 * another measured question; the compiler never invents their product. */
#define QUIC_JUNK_LEN 16u
#define QUIC_JUNK_REPEATS 1u
#define QUIC_UDPLEN_INCREMENT 100u

static int quic_arm_found(const d2k_quic_arm *a) {
    return a && (a->kind == D2K_QA_BLOB || a->kind == D2K_QA_COPIES ||
                 a->kind == D2K_QA_TTL || a->kind == D2K_QA_FRAG ||
                 a->kind == D2K_QA_SPLIT);
}

/* Задача 40: разрез ClientHello на два кадра CRYPTO внутри того же Initial —
   ответ вопроса стратегии, исполнитель 10 (quicsplit 1). Одно действие: ни
   приманок, ни «длины» — с ними сочетание не мерили. */
static int quic_split_plan_text(char *buf, size_t cap) {
    size_t pos = 0;
    return append_fmt(buf, cap, &pos,
                      "d2k-plan 1 10\nid 00000000000000000000000000000000\n"
                      "proto udp quic\nquicsplit 1\norder forward\n");
}

/* Один сборщик QUIC-плана на оба входа (плечо askArms и свойства вопросника)
   — та же склейка, что у compose донора, а не два похожих сборщика.
   arm == NULL — плеча нет; junk/udplen — подтверждённые свойства. */
static int quic_plan_text(const d2k_quic_arm *arm, const uint8_t *blob, size_t blen,
                          int junk, unsigned udplen, char *buf, size_t cap) {
    static const uint8_t junk_bytes[QUIC_JUNK_LEN];
    unsigned repeats = 1;
    int ttl = 0, frag = 0, has_fake = 0;
    const uint8_t *fake = NULL;
    size_t flen = 0;

    if (arm) {
        switch (arm->kind) {
        case D2K_QA_SPLIT:
            if(!arm->original || arm->frag_kind || arm->ttl) return -1;
            break;
        case D2K_QA_BLOB:   break;
        case D2K_QA_COPIES:
            if (arm->copies <= 0 || arm->copies > 255) { return -1; }
            repeats = (unsigned)arm->copies;
            break;
        case D2K_QA_TTL:
            if (arm->ttl <= 0 || arm->ttl > 255) { return -1; }
            ttl = arm->ttl;
            break;
        case D2K_QA_FRAG:
            if (!arm->original || arm->len || blen || !arm->frag_kind) return -1;
            break;
        default:
            return -1;
        }
        /* Original compose combines fake and fragment; no invented fake for a
           fragment-only result. Survival on the neutral control is mandatory. */
        frag = arm->frag_kind;
        has_fake = arm->kind != D2K_QA_FRAG;
        if (frag && (!arm->original || frag < 1 || frag > 4 ||
                     arm->frag_survives != D2K_PROP_YES)) return -1;
        if (arm->original) {
            if (has_fake && (arm->copies <= 0 || arm->copies > 255 ||
                arm->len == 0 || arm->len > sizeof arm->bytes || !blob ||
                blen != arm->len || memcmp(blob, arm->bytes, blen) != 0)) return -1;
            repeats = (unsigned)arm->copies;
        }
        if (has_fake && (!blob || blen == 0)) { return -1; }
        if (has_fake) { fake = blob; flen = blen; }
    }
    /* switch донора (questions.go:301-320): фальшивка плеча, а если её нет —
       мусор. Фрагментация от этого не зависит и склеивается с любым. */
    if (!has_fake && junk) {
        has_fake = 1;
        fake = junk_bytes;
        flen = sizeof junk_bytes;
        repeats = QUIC_JUNK_REPEATS;
        ttl = 0;
    }
    /* ФРАГМЕНТАЦИЯ ГАСИТ ДЛИНУ. У донора строка идёт
       `fake … send:ipfrag … drop udplen:increment=100`: send уже выпустил
       фрагменты НЕизменённой датаграммы, drop снял оригинал, и udplen правит
       пакет, которого на проводе не будет — DROP в zapret липкий
       (nfq2/desync.c, verdict_aggregate: MODIFY после DROP остаётся DROP).
       План описывает провод, поэтому длины в нём нет. */
    if (frag) { udplen = 0; }
    if (!has_fake && !frag && !udplen) { return -1; }

    size_t pos = 0;
    if (arm && arm->kind==D2K_QA_SPLIT) {
        if(append_fmt(buf,cap,&pos,"d2k-plan 1 10\nid 00000000000000000000000000000000\nproto udp quic\nquicsplit 1\n")!=0) return -1;
    } else if (frag) {
        if (append_fmt(buf,cap,&pos,"d2k-plan 1 7\nid 00000000000000000000000000000000\n"
                                   "proto udp quic\nipfrag %d\n",frag)!=0) return -1;
    } else if (udplen) {
        /* minexec=9: старый исполнитель записи udplen не знает и откажет
           громко, а не выпустит датаграмму без удлинения. */
        if (append_fmt(buf, cap, &pos, "d2k-plan 1 9\nid 00000000000000000000000000000000\n"
                                       "proto udp quic\n") != 0) return -1;
    } else if (emit_header_proto(buf, cap, &pos, "udp quic") != 0) { return -1; }
    if (has_fake) {
        if (append_fmt(buf, cap, &pos, "payload 1 ") != 0) { return -1; }
        if (append_hex(buf, cap, &pos, fake, flen) != 0) { return -1; }
        if (append_fmt(buf, cap, &pos, "\n") != 0) { return -1; }
        if (ttl) {
            if (append_fmt(buf, cap, &pos, "poison 1 ttl=%d\n", ttl) != 0) { return -1; }
        } else {
            if (append_fmt(buf, cap, &pos, "poison 1\n") != 0) { return -1; }
        }
        /* place=before и никакого «между»: между чем? Кусков у датаграммы нет.
           gap_us нулевой — паузы МЕЖДУ копиями донор не задаёт. У оригинального
           askArms нет дополнительной паузы перед правдой; pace только legacy. */
        if (append_fmt(buf, cap, &pos,
                       "fake payload=1 poison=1 repeats=%u gap_us=0 place=before\n",
                       repeats) != 0) {
            return -1;
        }
    }
    if (udplen) {
        /* The length question executes this same append action after the
           fresh Initial has been built; bytes inside the packet are intact. */
        if (append_fmt(buf, cap, &pos, "udplen %u\n", udplen) != 0) { return -1; }
    }
    if (append_fmt(buf, cap, &pos, "order forward\n") != 0) { return -1; }
    if (arm && !arm->original &&
        append_fmt(buf, cap, &pos, "pace %u\n", (unsigned)D2K_PACE_SETTLE_US) != 0) {
        return -1;
    }
    return 0;
}

int d2k_quic_arm_plan(const d2k_quic_arm *arm, const uint8_t *blob, size_t blen,
                      char *buf, size_t cap) {
    if (!arm || !arm->original || !buf || cap == 0 || !quic_arm_found(arm)) { return -1; }
    if (arm->kind == D2K_QA_SPLIT && !arm->len) {
        return arm->original && !blen ? quic_split_plan_text(buf, cap) : -1;
    }
    return quic_plan_text(arm, blob, blen, 0, 0, buf, cap);
}

int d2k_quic_compose_plan(const d2k_quic_arm *arm, const d2k_quic_props *p,
                          char *buf, size_t cap) {
    if (!p || !buf || cap == 0) { return -1; }
    /* Метки опытов не подтверждены — верить нельзя ни плечу, ни свойствам
       того же прогона. */
    if (arm && arm->kind == D2K_QA_FLAKY) { return -1; }
    if (arm && arm->kind == D2K_QA_SPLIT && !arm->len) {
        return arm->original && arm->len == 0 ? quic_split_plan_text(buf, cap) : -1;
    }
    const d2k_quic_arm *use = quic_arm_found(arm) ? arm : NULL;
    if(use)return d2k_quic_arm_plan(use,use->len?use->bytes:NULL,use->len,buf,cap);
    int junk=p->junk_ahead==D2K_PROP_YES;
    return quic_plan_text(NULL,NULL,0,junk,
        !junk && p->longer==D2K_PROP_YES?QUIC_UDPLEN_INCREMENT:0,buf,cap);
}

int d2k_quic_delay_plan(char *buf, size_t cap) {
    if (!buf || cap == 0) { return -1; }
    size_t pos = 0;
    /* minexec=6: выдержку перед единственной посылкой старый исполнитель не
       знает и молча выпустил бы её без паузы (см. d2k_plan.h). */
    if (append_fmt(buf, cap, &pos,
                   "d2k-plan 1 6\nid 00000000000000000000000000000000\n"
                   "proto udp quic\ndelay %u\n",
                   (unsigned)D2K_QUIC_DELAY_US) != 0) {
        return -1;
    }
    return 0;
}

int d2k_voice_arm_plan(const uint8_t *decoy, size_t dlen, unsigned copies,
                       char *buf, size_t cap) {
    if (!decoy || dlen == 0 || !buf || cap == 0 || copies == 0 || copies > 32) { return -1; }
    size_t pos = 0;
    if (emit_header_proto(buf, cap, &pos, "udp voice") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "payload 1 ") != 0) { return -1; }
    if (append_hex(buf, cap, &pos, decoy, dlen) != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "\npoison 1\n") != 0) { return -1; }
    /* Та же фигура, что у плеча QUIC: перед правдой, без паузы между
       копиями, выдержка перед правдой — pace. */
    if (append_fmt(buf, cap, &pos,
                   "fake payload=1 poison=1 repeats=%u gap_us=0 place=before\n",
                   copies) != 0) {
        return -1;
    }
    if (append_fmt(buf, cap, &pos, "order forward\n") != 0) { return -1; }
    if (append_fmt(buf, cap, &pos, "pace %u\n", (unsigned)D2K_PACE_SETTLE_US) != 0) {
        return -1;
    }
    return 0;
}

int d2k_voice_plan(const uint8_t *decoy, size_t dlen, char *buf, size_t cap) {
    return d2k_voice_arm_plan(decoy, dlen, D2K_VOICE_DECOY_REPEATS, buf, cap);
}


#include "d2k_udpruntime.h"
int d2k_quic_question_plan(const d2k_quic_arm_question *q,char *text,size_t cap) {
    if(!q || !text || !cap || q->blob_len>sizeof ((d2k_quic_arm *)0)->bytes ||
       (q->blob_len && !q->blob) || q->copies<0 || q->copies>255 ||
       q->ttl<0 || q->ttl>255 || (q->frag && (q->split || q->blob_len)))return -1;
    if(!q->blob_len && !q->split && !q->frag && !q->ttl)
        return snprintf(text,cap,"d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp quic\norder forward\n")>=(int)cap?-1:0;
    d2k_quic_arm a;memset(&a,0,sizeof a);a.original=1;
    a.kind=q->frag?D2K_QA_FRAG:q->split?D2K_QA_SPLIT:q->ttl?D2K_QA_TTL:D2K_QA_BLOB;
    a.frag_kind=q->frag;a.frag_survives=D2K_PROP_YES;
    a.ttl=q->ttl;a.copies=q->copies>0?q->copies:1;
    a.len=q->blob_len;
    if(a.len)memcpy(a.bytes,q->blob,a.len);
    return d2k_quic_arm_plan(&a,a.len?a.bytes:NULL,a.len,text,cap);
}
