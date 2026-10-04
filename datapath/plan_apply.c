/* plan_apply.c — превращение плана в список посылок для одного пакета.
 *
 * Договорённость о выводе, из которой следует всё остальное: список содержит
 * ТОЛЬКО то, что порождаем мы. Судьба оригинала — отдельное поле, а не ещё
 * одна строка в списке. Иначе «пропустить оригинал» и «выпустить его копию»
 * стали бы неразличимы, и пакет ушёл бы дважды.
 *
 * Отсюда правило: если план выпускает нагрузку сам (есть разрезы или
 * перекрытие), оригинал снимается. Если план только добавляет фальшивку —
 * оригинал пропускается, а наши посылки идут перед ним.
 *
 * Плавающей арифметики здесь нет: MIPS-коробки без сопроцессора, и каждая
 * операция с double там становится вызовом libgcc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "d2k_plan.h"
#include "plan_internal.h"
#include "d2k_quic.h" /* d2k_quic_initial_split_crypto — задача 40 */

/* Разрешение якоря. Невычислимый якорь — ОТКАЗ, а не нулевое смещение:
 * молчаливый ноль исполнил бы не тот план, который измеряли. */
static int anchor_offset(const d2k_pkt *in, uint16_t anchor, size_t *out) {
    switch (anchor) {
    case ANCHOR_PAYLOAD_START:
        *out = 0;
        return 0;
    case ANCHOR_SNI_START:
        if (!in->have_sni) {
            return -1;
        }
        *out = in->sni_off;
        return 0;
    case ANCHOR_SNI_END:
        if (!in->have_sni) {
            return -1;
        }
        *out = in->sni_off + in->sni_len;
        return 0;
    case ANCHOR_HELLO_MIDDLE:
        *out = in->payload_len / 2;
        return 0;
    case ANCHOR_SNI_MIDDLE:
        /* Середина ИМЕНИ хоста, а не середина пакета. Коробка ищет имя
           целиком; ANCHOR_HELLO_MIDDLE чаще оставляет имя нетронутым в одном
           куске (осмысленное начало записи), и коробка спокойно ждёт
           остаток — разрез не срабатывает. Донор наступил на эту же ошибку
           и исправил её тем же замером: боевое плечо режет на midsld,
           середине домена второго уровня, а не на n/2
           (z2k-detect/internal/classify/raw_linux.go:667-690). */
        if (!in->have_sni) {
            return -1;
        }
        /* Зажимы дословно донорские: без них короткое имя даёт вырожденный
           (меньше 2) или пустой/переполненный (>= длины нагрузки) кусок. */
        *out = in->sni_off + in->sni_len / 2;
        if (*out < 2) {
            *out = 2;
        }
        if (*out >= in->payload_len) {
            *out = in->payload_len - 1;
        }
        return 0;
    case ANCHOR_RECORD_END:
        /* Границу записи TLS обязан передать протокольный модуль. Пока он не
           написан, честный ответ — отказ, а не догадка о длине. */
        return -1;
    default:
        return -1;
    }
}

static int cmp_size(const void *a, const void *b) {
    size_t x = *(const size_t *)a, y = *(const size_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/* Позиции разрезов: якорь плюс смещение, отсортированы по возрастанию и
 * очищены от повторов и краёв. Порядок именно возрастающий, а не порядок
 * записей: иначе перестановка записей в плане меняла бы куски. */
static int split_points(const d2k_plan *p, const d2k_pkt *in,
                        size_t *pts, size_t *n_out) {
    size_t n = 0;
    for (size_t i = 0; i < p->n_splits; i++) {
        size_t base;
        if (anchor_offset(in, p->splits[i].anchor, &base) != 0) {
            return -1;
        }
        long v = (long)base + p->splits[i].offset;
        if (v <= 0 || (size_t)v >= in->payload_len) {
            /* Разрез вне нагрузки не режет ничего. Это не отказ: якорь
               вычислился, просто пакет короче. */
            continue;
        }
        pts[n++] = (size_t)v;
    }
    if (n > 1) {
        qsort(pts, n, sizeof *pts, cmp_size);
        size_t w = 1;
        for (size_t i = 1; i < n; i++) {
            if (pts[i] != pts[w - 1]) {
                pts[w++] = pts[i];
            }
        }
        n = w;
    }
    *n_out = n;
    return 0;
}

static int tls_ch_layout(const uint8_t *b, size_t n, int allow_prefix, size_t *rnd_off,
                         size_t *sid_off, size_t *sid_len) {
    if (!b || n < 44 || b[0] != 0x16 || b[1] != 3 || b[5] != 1) { return -1; }
    size_t rec_len = ((size_t)b[3] << 8) | b[4];
    size_t hs_len = ((size_t)b[6] << 16) | ((size_t)b[7] << 8) | b[8];
    if (rec_len + 5 != hs_len + 9 || n > rec_len + 5 ||
        (!allow_prefix && (hs_len > n - 9 || rec_len > n - 5))) { return -1; }
    size_t len_off = 43;
    size_t sl = b[len_off];
    if (sl > 32 || sl > n - (len_off + 1)) { return -1; }
    *rnd_off = 11; *sid_off = len_off + 1; *sid_len = sl;
    return 0;
}

static int random_bytes(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { return -1; }
    size_t got = fread(out, 1, n, f);
    int bad = ferror(f);
    fclose(f);
    return got == n && !bad ? 0 : -1;
}

static void wr16(uint8_t *b, size_t off, size_t v) {
    b[off] = (uint8_t)(v >> 8); b[off + 1] = (uint8_t)v;
}
static void wr24(uint8_t *b, size_t off, size_t v) {
    b[off] = (uint8_t)(v >> 16); b[off + 1] = (uint8_t)(v >> 8);
    b[off + 2] = (uint8_t)v;
}

static int fake_tls_bytes(const d2k_plan *p, const struct d2k_fake *f,
                          const struct d2k_payload *pl, const d2k_pkt *in,
                          uint8_t **owned) {
    size_t fake_rnd, fake_sid, fake_sid_len;
    size_t real_rnd, real_sid, real_sid_len;
    *owned = NULL;
    if (!in->is_tls13 || tls_ch_layout(in->payload, in->payload_len,
            p->wire_profile == D2K_WIRE_TCP_TEMPLATE,
            &real_rnd, &real_sid, &real_sid_len) != 0 ||
        tls_ch_layout(pl->bytes, pl->len, 0, &fake_rnd, &fake_sid,
                      &fake_sid_len) != 0) { return -1; }
    if (p->wire_profile == D2K_WIRE_TCP_TEMPLATE) {
        /* Original TLSMod: randomize fake random/SID, then duplicate SID only
         * when lengths match. It does not resize fake_default_tls. */
        uint8_t *b = malloc(pl->len);
        if (!b) return -1;
        memcpy(b, pl->bytes, pl->len);
        if ((f->tls_mod & D2K_TLS_MOD_RND) &&
            (random_bytes(b + fake_rnd, 32) != 0 ||
             random_bytes(b + fake_sid, fake_sid_len) != 0)) {
            free(b); return -1;
        }
        if ((f->tls_mod & D2K_TLS_MOD_DUPSID) && fake_sid_len == real_sid_len)
            memcpy(b + fake_sid, in->payload + real_sid, real_sid_len);
        *owned = b;
        return 0;
    }
    size_t out_len = pl->len;
    if (f->tls_mod & D2K_TLS_MOD_DUPSID) {
        out_len = pl->len - fake_sid_len + real_sid_len;
        if (out_len > 65540 || out_len < 9 || out_len - 5 > 65535 || out_len - 9 > 0xffffff) { return -1; }
    }
    uint8_t *b = malloc(out_len);
    if (!b) { return -1; }
    if (f->tls_mod & D2K_TLS_MOD_DUPSID) {
        memcpy(b, pl->bytes, fake_sid);
        memcpy(b + fake_sid, in->payload + real_sid, real_sid_len);
        memcpy(b + fake_sid + real_sid_len, pl->bytes + fake_sid + fake_sid_len,
               pl->len - fake_sid - fake_sid_len);
        b[fake_sid - 1] = (uint8_t)real_sid_len;
        wr16(b, 3, out_len - 5);
        wr24(b, 6, out_len - 9);
    } else {
        memcpy(b, pl->bytes, pl->len);
    }
    if ((f->tls_mod & D2K_TLS_MOD_RND) && random_bytes(b + fake_rnd, 32) != 0) {
        free(b); return -1;
    }
    (void)p;
    *owned = b;
    return 0;
}

static int emit_fake(d2k_emit *e, const d2k_plan *p, const struct d2k_fake *f,
                     const d2k_pkt *in, uint32_t seq, uint32_t delay) {
    const struct d2k_payload *pl = d2k_find_payload(p, f->payload_id);
    const struct d2k_poison *po = f->poison_id ? d2k_find_poison(p, f->poison_id) : NULL;
    if (!pl) { return -1; }
    memset(e, 0, sizeof *e);
    e->kind = D2K_EMIT_FAKE;
    e->delay_us = delay;
    e->seq = seq;
    e->bytes = pl->bytes;
    e->len = pl->len;
    if (f->tls_mod) {
        if (fake_tls_bytes(p, f, pl, in, &e->owned_bytes) != 0) { return -1; }
        e->bytes = e->owned_bytes;
    }
    if (po) {
        e->ttl = po->ttl;
        e->poison = po->flags;
        e->seq_shift = po->seq_shift;
    }
    return 0;
}

static void emit_vec_free(d2k_emit *v, size_t n) {
    if (!v) { return; }
    for (size_t i = 0; i < n; i++) { free(v[i].owned_bytes); }
    free(v);
}

/* Заголовки на проводе — те же числа, что у сборщиков (wire.c, wire_udp.c).
   Повторены здесь, а не вынесены в общий заголовок, по тому же правилу, по
   которому wire_udp.c держит собственные копии wr16/sum16: модули пакетного
   пути самодостаточны. Расхождение поймает test_ctl: он сверяет 20+20+длина
   приманки с тем, что реально собирает wire.c. */
#define EMIT_IP_HDR   20
#define EMIT_TCP_HDR  20
#define EMIT_UDP_HDR   8
/* Метка времени TCP: NOP, NOP, тип 8, длина 10 — см. TS_OPT_LEN в wire.c. */
#define EMIT_TS_OPT   12

static size_t emit_overhead(const d2k_plan *p, const struct d2k_poison *po) {
    /* Транспорт не объявлен — считаем по TCP: его заголовок шире, и ошибка в
       эту сторону отвергает лишнее, а не пропускает непроходимое. */
    size_t hdr = EMIT_IP_HDR + ((p->transport == 17) ? EMIT_UDP_HDR : EMIT_TCP_HDR);
    if (po && (po->flags & D2K_POISON_TCPTS_BACK) && p->transport != 17) {
        hdr += EMIT_TS_OPT;
    }
    return hdr;
}

size_t d2k_plan_max_emit(const d2k_plan *p) {
    if (!p) {
        return 0;
    }
    size_t max = 0;
    for (size_t i = 0; i < p->n_fakes; i++) {
        const struct d2k_payload *pl = d2k_find_payload(p, p->fakes[i].payload_id);
        if (!pl) {
            continue;   /* висячая ссылка отвергается разбором, сюда не доходит */
        }
        const struct d2k_poison *po = p->fakes[i].poison_id
            ? d2k_find_poison(p, p->fakes[i].poison_id) : NULL;
        size_t body = pl->len + ((p->fakes[i].tls_mod & D2K_TLS_MOD_DUPSID) ? 32u : 0u);
        if (p->segment_size && body > p->segment_size) { body = p->segment_size; }
        size_t n = emit_overhead(p, po) + body;
        if (n > max) { max = n; }
    }
    for (size_t i = 0; i < p->n_seqovls; i++) {
        const struct d2k_payload *pl = d2k_find_payload(p, p->seqovls[i].payload_id);
        if (!pl) {
            continue;
        }
        const struct d2k_poison *po = p->seqovls[i].poison_id
            ? d2k_find_poison(p, p->seqovls[i].poison_id) : NULL;
        /* Только приставка: кусок нагрузки, к которому она приклеивается,
           приходит из пакета — см. d2k_plan_max_emit в d2k_plan.h про то,
           почему он здесь не считается. */
        size_t body = pl->len;
        if (p->segment_size && body > p->segment_size) { body = p->segment_size; }
        size_t n = emit_overhead(p, po) + body;
        if (n > max) { max = n; }
    }
    if (p->udplen) {
        /* Удлинённая датаграмма — посылка, которую план объявляет сам: к
           любой пришедшей нагрузке он добавит udplen байт. Сама нагрузка
           зависит от пакета, но у QUIC её нижняя граница задана стандартом:
           клиентский Initial не короче 1200 байт (RFC 9000 §14.1). Без этого
           способ отправки, не уносящий 1328 байт, узнал бы о том только
           отказом ядра уже после APPLIED. */
        size_t body = (p->proto == 2 ? 1200u : 1u) + p->udplen;
        size_t n = emit_overhead(p, NULL) + body;
        if (n > max) { max = n; }
    }
    return max;
}

int d2k_plan_apply(const d2k_plan *p, const d2k_flow *f,
                   const d2k_pkt *in, d2k_actions *out) {
    (void)f;
    if (!p || !in || !out) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (!in->payload || in->payload_len == 0) {
        return -1;
    }
    /* HTTP-план — только запросу HTTP, прочий план — только не ему (шаг 4
       задачи 51): якоря «sni_*» у них считаются от разного. */
    if ((p->proto == D2K_PLAN_PROTO_HTTP) != (in->is_http != 0)) {
        return -1;
    }
    if (p->qdeny) {
        /* Не воздействие: оригинал снимается, посылок нет (сессия решает
           это раньше; здесь — чтобы исполнитель не выдумал иного). */
        out->fate = D2K_ORIG_DROP;
        return 0;
    }
    if (in->is_http && (p->input_tls || p->input_len || p->oob_enabled || p->ipfrag ||
                        p->udplen || p->qsplit)) {
        return -1;
    }
    if (p->input_tls) {
        /* SNI-relative actions are reusable, but a first TCP fragment is
         * not the full input on which raw.c performs its three-part send.
         * SNI metadata is provided by the normal session TLS parser. */
        const uint8_t *b = in->payload;
        size_t n = in->payload_len;
        if (n < 9 || n > 2048 || b[0] != 0x16 || b[1] != 3 || b[5] != 1 ||
            !in->have_sni || in->sni_len <= 1 || !in->sni_off ||
            in->sni_off > n || in->sni_len > n - in->sni_off) { return -1; }
        /* ЗАПИСЬ ЦЕЛИКОМ ИЛИ ЕЁ НАЧАЛО — ВХОД В ОБОИХ СЛУЧАЯХ.
         *
         * Приветствие длиннее сегмента — обычное дело: 1534 байта при MSS
         * 1388 (поле 18.09.2026, приветствие Discord). Прежде требовалось
         * совпадение объявленной длины с пришедшей, и такому потоку план не
         * применялся вовсе — «план неприменим к этому пакету». Дождаться
         * остатка и собрать целое нельзя: пока первый сегмент лежит в
         * очереди без вердикта, ядро остаток НЕ ВЫПУСКАЕТ (тот же замер, три
         * прогона: «начато=2, таймаутов=2, добавлено к голове=0» — второй
         * сегмент до сборщика не доходил ни разу, его не отвергали).
         *
         * Для действий плана целой записи и не нужно: имя в сегменте есть,
         * разрезы считаются от него, а остаток уйдёт на провод сам, следом за
         * нашими кусками — ровно как у донора с выключенной пересборкой.
         * Требование остаётся одно: объявленные длины сходятся между собой, и
         * пришло не больше объявленного. Байты, собранные под конкретный вход
         * (input_len ниже), по-прежнему требуют своего входа до байта. */
        size_t rec_total = 5u + ((size_t)b[3] << 8) + b[4];
        size_t hs_total = 9u + ((size_t)b[6] << 16) + ((size_t)b[7] << 8) + b[8];
        if (rec_total != hs_total || n > rec_total) { return -1; }
    }
    if (p->input_len &&
        (in->payload_len != p->input_len ||
         (in->have_sni ? in->sni_len : 0) != p->input_sni_len ||
         (p->input_sni_len && in->sni_off != p->input_sni_off))) {
        return -1; /* not the input for which fixed measured bytes were built */
    }

    if (p->oob_enabled) {
        size_t mid = 0;
        if (anchor_offset(in, p->oob_anchor, &mid) != 0 ||
            mid == 0 || mid >= in->payload_len) { return -1; }
        d2k_emit *v = calloc(3, sizeof *v);
        if (!v) { return -1; }
        v[0].kind = D2K_EMIT_PAYLOAD;
        v[0].seq = in->seq;
        v[0].bytes = in->payload;
        v[0].len = mid;

        v[1].kind = D2K_EMIT_PAYLOAD;
        v[1].seq = in->seq + (uint32_t)mid;
        v[1].bytes = &p->oob_byte;
        v[1].len = 1;
        v[1].urgent = 1;
        v[1].urgent_ptr = 1;

        /* TCP sequence space includes urgent data even though the receiving
           application normally removes that byte from its in-band stream.
           Therefore replay the original suffix unchanged at seq+mid+1. */
        v[2].kind = D2K_EMIT_PAYLOAD;
        v[2].seq = in->seq + (uint32_t)mid + 1u;
        v[2].bytes = in->payload + mid;
        v[2].len = in->payload_len - mid;

        out->fate = D2K_ORIG_DROP;
        out->n = 3;
        out->v = v;
        return 0;
    }

    size_t *pts = NULL;
    size_t n_pts = 0;
    if (p->n_splits) {
        pts = calloc(p->n_splits, sizeof *pts);
        if (!pts) {
            return -1;
        }
        if (split_points(p, in, pts, &n_pts) != 0) {
            free(pts);
            return -1; /* невычислимый якорь */
        }
    }

    /* Разнос во времени тоже означает владение нагрузкой: выдержать паузу
       перед правдой можно только тогда, когда правду выпускаем мы сами.
       Оригинал, отпущенный ядром, уходит когда ему угодно. */
    int owns_payload = (n_pts > 0) || (p->n_seqovls > 0) || (p->pace_us > 0) ||
                       (p->settle_us > 0) || (p->delay_us > 0) || p->ipfrag ||
                       p->udplen || p->qsplit;
    /* Оригинал, отданный ядру после наших сырых фальшивок, может не уйти
       вовсе (см. own_after_fakes в d2k_plan.h). Тогда правда — последняя
       посылка плана, сразу за фальшивками, без собственной паузы. */
    /* Задача 47: не только фальшивки «перед». Любая сырая посылка плана
       выходит раньше вердикта оригинала (d2kd шлёт посылки до вердикта, а
       отложенные — до отложенного вердикта), и запись создаёт она. Поэтому
       при own_after_fakes оригинал — всегда посылка плана, если фальшивки
       есть вообще. Сегодня у датаграммы другого места для фальшивки нет
       («между» требует разрезов, а UDP их не допускает), так что это
       закрепление правила, а не новое поведение. */
    if (in->own_after_fakes && p->n_fakes > 0) {
        owns_payload = 1;
    }
    if (p->udplen && in->payload_len + (size_t)p->udplen > 65535u - 8u) {
        free(pts);
        return -1; /* удлинённая нагрузка не помещается в одну UDP-датаграмму */
    }

    /* Верхняя оценка числа посылок: копии фальшивок плюс куски. Считаем
       заранее, чтобы выделить память один раз.
     *
     * ФАЛЬШИВКА «МЕЖДУ КУСКАМИ» ВЫПУСКАЕТСЯ В КАЖДЫЙ РАЗРЕЗ, а не один раз на
     * план: разрезов n_pts, и мест для неё столько же. Прежняя оценка считала
     * её однократной, и с ДВУМЯ разрезами исполнитель писал за границу
     * выделенного массива — на живом стенде 13.09.2026 это валило датапат
     * (`malloc(): corrupted top size`). С одним разрезом оценка совпадала со
     * счётом случайно, потому и прожило незамеченным: ни один тест не ставил
     * второго разреза рядом с такой фальшивкой.
     *
     * Фальшивки «между» учитываются ТОЛЬКО при owns_payload: без собственной
     * нагрузки кусков нет, разрезать нечего, и разбор их вовсе не принимает
     * (plan_parse.c: «между кусками» без разрезов — негодный план). */
    size_t max_emits = 0;
    size_t between_per_gap = 0;
    for (size_t i = 0; i < p->n_fakes; i++) {
        uint8_t r = p->fakes[i].repeats;
        size_t reps = (r == 0 ? 1 : (size_t)r);
        if (p->fakes[i].placement == PLACE_BETWEEN) {
            between_per_gap += reps;
        } else {
            max_emits += reps;
        }
    }
    if (owns_payload) {
        max_emits += n_pts + 1;
        max_emits += n_pts * between_per_gap;
    }
    if (max_emits == 0) {
        free(pts);
        out->fate = D2K_ORIG_PASS;
        return 0;
    }

    d2k_emit *v = calloc(max_emits, sizeof *v);
    if (!v) {
        free(pts);
        return -1;
    }
    size_t n = 0;

    /* Фальшивки, стоящие перед всеми кусками. */
    for (size_t i = 0; i < p->n_fakes; i++) {
        if (p->fakes[i].placement != PLACE_BEFORE) {
            continue;
        }
        uint8_t reps = p->fakes[i].repeats ? p->fakes[i].repeats : 1;
        for (uint8_t r = 0; r < reps; r++) {
            if (emit_fake(&v[n], p, &p->fakes[i], in, in->seq,
                          r == 0 ? 0 : p->fakes[i].gap_us) != 0) {
                free(pts); emit_vec_free(v, n); return -1;
            }
            if (r && p->wire_profile == D2K_WIRE_TCP_TEMPLATE && v[n].owned_bytes) {
                /* repeats retransmits the same mutated fake, not eight
                 * independently randomized ClientHellos. */
                memcpy(v[n].owned_bytes, v[n - r].bytes, v[n].len);
            }
            n++;
        }
    }

    if (owns_payload) {
        /* ПЕРЕКРЫТИЕ. Первый кусок выходит с номером на длину приставки
           МЕНЬШЕ, чем начало нагрузки, и несёт эту приставку впереди.
           Сервер выбросит её как уже полученное и склеит нагрузку верно;
           коробка, складывающая поток по порядку прихода, положит приставку
           в поток и разберёт не то, что разберёт сервер.
           Это ответ на коробку, которая ПЕРЕСОБИРАЕТ: разрез её не берёт,
           потому что она склеивает куски, а вот отравить склейку можно. */
        const struct d2k_payload *ovl = NULL;
        const struct d2k_poison  *ovl_po = NULL;
        if (p->n_seqovls > 0) {
            ovl = d2k_find_payload(p, p->seqovls[0].payload_id);
            if (p->seqovls[0].poison_id) {
                ovl_po = d2k_find_poison(p, p->seqovls[0].poison_id);
            }
        }

        size_t start = 0;
        for (size_t i = 0; i <= n_pts; i++) {
            size_t end = (i < n_pts) ? pts[i] : in->payload_len;
            d2k_emit *e = &v[n++];
            memset(e, 0, sizeof *e);
            e->kind = D2K_EMIT_PAYLOAD;
            e->ipfrag = p->ipfrag;
            /* Разнос проставляется НЕ здесь, а после возможного переворота
               порядка: задержка — свойство МЕСТА в очереди отправки, а не
               куска. Уехав вместе с куском, она сделала бы паузу перед первой
               же посылкой и отменила бы её перед последней. */
            e->delay_us = 0;
            e->seq = in->seq + (uint32_t)start;
            e->bytes = in->payload + start;
            e->len = end - start;
            if (p->qsplit) {
                /* Тот же разрез, что задал вопрос замера (ядро), в копии:
                   вход принадлежит пакету. Разрезов при qsplit нет
                   (plan_parse.c), кусок один и он весь пакет. Не Initial,
                   чужой кадр, нет добивки — отказ целиком: пакет уйдёт
                   нетронутым, а не «почти так, как мерили». */
                uint8_t *re = malloc(e->len);
                size_t re_len = 0;
                int src = re ? d2k_quic_initial_split_crypto(e->bytes, e->len, re, e->len,
                                                             &re_len) : -1;
                if (src != 0 || re_len != e->len) {
                    /* Причина — вызывающему (журнал отказов): разрез, которого
                       не мерили, не выдаётся за применённый план. */
                    out->refuse_why = src == D2K_QUIC_SPLIT_NO_NAME
                        ? "разрез CRYPTO: имени нет в этой датаграмме "
                          "(ClientHello шире датаграммы) — такой разрез не мерили"
                        : "разрез CRYPTO неприменим: не Initial, чужой кадр или нет добивки";
                    free(re); free(pts); emit_vec_free(v, n); return -1;
                }
                e->owned_bytes = re;
                e->bytes = re;
            }
            if (p->udplen) {
                /* zapret udplen: payload .. pattern("\x00", 1, increment).
                   Копия, а не правка на месте: вход принадлежит пакету, и
                   отмена обязана отпустить его нетронутым. Разрезов при
                   udplen нет (plan_parse.c), кусок один и он весь пакет. */
                uint8_t *grown = malloc(e->len + p->udplen);
                if (!grown) { free(pts); emit_vec_free(v, n); return -1; }
                memcpy(grown, e->bytes, e->len);
                memset(grown + e->len, 0, p->udplen);
                e->owned_bytes = grown;
                e->bytes = grown;
                e->len += p->udplen;
            }
            if (i == 0 && ovl && ovl->len > 0) {
                e->pre = ovl->bytes;
                e->pre_len = ovl->len;
                e->seq = in->seq - (uint32_t)ovl->len;
                if (ovl_po) {
                    e->ttl = ovl_po->ttl;
                    e->poison = ovl_po->flags;
                    e->seq_shift = ovl_po->seq_shift;
                }
            }
            start = end;

            /* Фальшивка между кусками — после каждого, кроме последнего. */
            if (i < n_pts) {
                for (size_t k = 0; k < p->n_fakes; k++) {
                    if (p->fakes[k].placement != PLACE_BETWEEN) {
                        continue;
                    }
                    uint8_t reps = p->fakes[k].repeats ? p->fakes[k].repeats : 1;
                    for (uint8_t r = 0; r < reps; r++) {
                        if (emit_fake(&v[n], p, &p->fakes[k], in,
                                      in->seq + (uint32_t)start,
                                      r == 0 ? 0 : p->fakes[k].gap_us) != 0) {
                            free(pts); emit_vec_free(v, n); return -1;
                        }
                        n++;
                    }
                }
            }
        }

        if (p->order == ORDER_REVERSE) {
            /* Переворачиваем только куски нагрузки, не фальшивки: смысл
               обратного порядка в том, что хвост приветствия уходит раньше
               головы, а фальшивка обязана остаться там, куда её поставили.
               Фальшивка PLACE_BETWEEN стоит ВНУТРИ диапазона кусков — она
               выпущена между ними, а не по краям. Диапазонный переворот
               («найти границы и перевернуть весь кусок памяти») утащил бы её
               вместе с нагрузкой, хотя комментарий выше обещает обратное.
               Нужен обмен по конкретным посылкам нагрузки, а не по границам
               диапазона.

               Раньше кусок отыскивали сравнением v[i].bytes с in->payload:
               указатель фальшивки — из буфера плана, указатель нагрузки — из
               буфера пакета, а это разные выделения памяти. Сравнение таких
               указателей оператором `<` не определено языком и «работало»
               только при удачной случайной раскладке кучи. kind проставлен
               явно при формировании каждой посылки (emit_fake ставит
               D2K_EMIT_FAKE, кусок нагрузки — D2K_EMIT_PAYLOAD чуть выше),
               и сравнение через него определено всегда, а не по счастливой
               случайности.

               Схождение двух указателей навстречу друг другу без выделения
               памяти: i и j — size_t, i только растёт, j только убывает, и
               j - 1 ниже вычисляется исключительно когда цикл уже проверил
               i < j, то есть j >= 1. Переполнения размера нет ни на одном
               шаге, поэтому единственный кусок (или вовсе пустой диапазон)
               оставляет цикл без единой итерации, а не пишет за пределы v —
               раньше при hi == lo это же место разности `j - 1` при j == 0
               уходило в беззнаковое переполнение и писало за границу массива. */
            size_t i = 0, j = n;
            while (i < j) {
                if (v[i].kind != D2K_EMIT_PAYLOAD) {
                    i++;
                    continue;
                }
                if (v[j - 1].kind != D2K_EMIT_PAYLOAD) {
                    j--;
                    continue;
                }
                if (i + 1 >= j) {
                    /* Между указателями остался один кусок нагрузки или
                       ни одного — меняться больше нечему. */
                    break;
                }
                d2k_emit t = v[i];
                v[i] = v[j - 1];
                v[j - 1] = t;
                i++;
                j--;
            }
        }
    }

    /* РАЗНОС ВО ВРЕМЕНИ — позиционно, после всех перестановок.
     *
     * Пауза стоит перед каждой посылкой НАГРУЗКИ, кроме самой первой посылки
     * плана: перед ней ждать не перед чем. Фальшивки не трогаем — у них своя
     * пауза между копиями (gap_us), и приём «серия вплотную» с ней и
     * задуман; наложив сюда же общий разнос, мы превратили бы одно плечо в
     * другое.
     *
     * Обе формы донора закрываются этим одним правилом: три куска с паузой
     * между ними (фальшивок нет — первый уходит сразу) и выдержка между
     * последней фальшивкой и правдой (первой идёт фальшивка — нагрузка ждёт).
     */
    if (p->pace_us > 0) {
        for (size_t i = 0; i < n; i++) {
            if (v[i].kind != D2K_EMIT_PAYLOAD) { continue; }
            v[i].delay_us = (i == 0) ? 0 : p->pace_us;
        }
    }

    if (p->settle_us > 0) {
        for (size_t i = 0; i < n; i++) {
            if (v[i].kind != D2K_EMIT_PAYLOAD) { continue; }
            if (i > 0) { v[i].delay_us = p->settle_us; }
            break;
        }
    }

    /* ВЫДЕРЖКА ПЕРЕД ПЕРВОЙ НАГРУЗКОЙ — независимо от того, стоит ли что-то
       перед ней. Этим и отличается от settle, который молчит на посылке с
       нулевым номером (см. d2k_plan_internal.h про delay_us). */
    if (p->delay_us > 0) {
        for (size_t i = 0; i < n; i++) {
            if (v[i].kind != D2K_EMIT_PAYLOAD) { continue; }
            v[i].delay_us = p->delay_us;
            break;
        }
    }
    free(pts);
    for (size_t i = 0; i < n; i++) { v[i].wire_profile = p->wire_profile; }
    if (p->segment_size || in->segment_cap) {
        /* Match raw_send: split the concatenated prefix+body, preserving
         * bytes, sequence space, fooling and only the first chunk's delay.
         * Route MTU also bounds ordinary TCP payloads: a paced or split
         * plan can own a reassembled ClientHello larger than one packet.
         * The route cap does not segment fake packets, UDP, or explicit
         * IP-fragment plans; an explicit segment_size keeps its semantics. */
        size_t count = 0;
        for (size_t i = 0; i < n; i++) {
            size_t bytes = v[i].pre_len + v[i].len;
            size_t limit = p->segment_size;
            if (in->segment_cap && (!p->transport || p->transport == 6) &&
                !p->ipfrag && v[i].kind == D2K_EMIT_PAYLOAD &&
                (!limit || in->segment_cap < limit)) {
                limit = in->segment_cap;
            }
            size_t chunks = limit && bytes ? (bytes - 1) / limit + 1 : 1;
            if (chunks > 65536 || count > 65536 - chunks) { emit_vec_free(v, n); return -1; }
            count += chunks;
        }
        d2k_emit *split = calloc(count, sizeof *split);
        if (!split) { emit_vec_free(v, n); return -1; }
        size_t k = 0;
        for (size_t i = 0; i < n; i++) {
            size_t limit = p->segment_size;
            if (in->segment_cap && (!p->transport || p->transport == 6) &&
                !p->ipfrag && v[i].kind == D2K_EMIT_PAYLOAD &&
                (!limit || in->segment_cap < limit)) {
                limit = in->segment_cap;
            }
            size_t total = v[i].pre_len + v[i].len, off = 0;
            do {
                d2k_emit *e = &split[k++];
                *e = v[i];
                size_t take = total - off;
                if (limit && take > limit) { take = limit; }
                e->seq += (uint32_t)off;
                if (off) { e->delay_us = 0; }
                e->pre_len = off < v[i].pre_len ? v[i].pre_len - off : 0;
                if (e->pre_len > take) { e->pre_len = take; }
                e->pre = e->pre_len ? v[i].pre + off : NULL;
                e->len = take - e->pre_len;
                e->bytes = e->len ? v[i].bytes + (off > v[i].pre_len ? off - v[i].pre_len : 0) : NULL;
                e->owned_bytes = off == 0 ? v[i].owned_bytes : NULL;
                off += take;
            } while (off < total);
            v[i].owned_bytes = NULL; /* ownership transferred to first chunk */
        }
        emit_vec_free(v, n); v = split; n = count;
    }
    out->v = v;
    out->n = n;
    out->fate = owns_payload ? D2K_ORIG_DROP : D2K_ORIG_PASS;
    return 0;
}

/* Отмена исполнения на середине.
 *
 * Три правила, и все три следуют из одного: коробка уже увидела часть того,
 * что мы собирались показать, и вернуть это назад нельзя.
 *
 * 1. Пока нагрузку не трогали — оригинал отпускается. Он цел, и потерять его
 *    значило бы оборвать соединение человеку из-за нашей внутренней причины.
 * 2. Как только ушёл хоть один кусок нагрузки — чистого выхода нет. Отпустить
 *    оригинал значит послать те же байты дважды, не отпустить — потерять
 *    остаток. Поток испорчен, и исполнитель сообщает об этом фактом, а не
 *    выбирает меньшее зло сам: что делать с испорченным потоком — политика
 *    контроллера.
 * 3. Любая незавершённая отправка делает исполнение неполным. По нему нельзя
 *    записывать ни успех, ни неудачу: коробка видела не тот набор пакетов,
 *    который описывает план, а §2.3 запрещает сохранять неподтверждённое.
 */
void d2k_actions_cancel(const d2k_actions *a, size_t emitted, d2k_cancel *out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof *out);
    if (!a) {
        out->fate = D2K_ORIG_PASS;
        return;
    }
    if (emitted > a->n) {
        emitted = a->n;
    }

    int payload_out = 0;
    for (size_t i = 0; i < emitted; i++) {
        if (a->v[i].kind == D2K_EMIT_PAYLOAD) {
            payload_out = 1;
            break;
        }
    }

    out->partial = (emitted < a->n) ? 1 : 0;
    out->stream_damaged = (payload_out && emitted < a->n) ? 1 : 0;

    if (payload_out) {
        /* Байты нагрузки уже на проводе: повторять их нельзя. */
        out->fate = D2K_ORIG_DROP;
    } else {
        out->fate = D2K_ORIG_PASS;
    }
}

void d2k_actions_free(d2k_actions *a) {
    if (!a) {
        return;
    }
    for (size_t i = 0; i < a->n; i++) { free(a->v[i].owned_bytes); }
    free(a->v);
    a->v = NULL;
    a->n = 0;
}
