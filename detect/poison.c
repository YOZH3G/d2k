/* poison.c — гипотезы отравления и перевод находки в строку стратегии.
 *
 * Перенос internal/classify/classify.go эталона (poisons, strategyForPoison,
 * strategyFor, notePropsHit, notePropsMiss) — дословный, включая ПОРЯДОК.
 * Порядок здесь не косметика: неудачный зонд ждёт весь таймаут, удачный
 * отвечает мгновенно и обрывает перебор, поэтому первыми идут гипотезы,
 * которые уже брали живые коробки.
 */
#include "d2k_detect.h"

#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

int d2k_poison_supports_family(const d2k_poison *p, uint8_t family)
{
    /* IPv6 has no IPv4 Identification field. Do not measure an impossible
       wire hypothesis and record its local construction error as a block. */
    return p && (family == 4 || (family == 6 && !p->ip_id_zero));
}

int d2k_poison_has_fake(const d2k_poison *p)
{
    /* synData и oob фальшивки не несут вовсе, fakeBetween ставит её сам и в
     * другом месте — общий путь отправки для них не годится. */
    if (p->syn_data || p->oob || p->fake_between) {
        return 0;
    }
    /* Метка времени со сдвигом назад — тоже подделка: сервер отбросит её по
     * PAWS (§0.1, поле 07.10.2026 — вопрос «метка времени» без неё слал
     * обычное приветствие, и «проход» был ложным). */
    return p->badsum || p->md5 || p->ttl > 0 || p->seq_shift != 0 || p->tcp_ts;
}

static int push(d2k_sends *o, int kind, int64_t off, const uint8_t *b, size_t len,
                const d2k_poison *p, int delay_ms)
{
    d2k_send *s;
    if (o->n >= D2K_SEND_MAX) {
        return -1;
    }
    s = &o->v[o->n++];
    memset(s, 0, sizeof(*s));
    s->kind = kind;
    s->seq_off = off;
    s->bytes = b;
    s->len = len;
    if (p) {
        s->poison = *p;
    }
    s->delay_ms = delay_ms;
    return 0;
}

/* Середина имени, если оно известно, иначе середина приветствия; в [2, n-1]. */
static size_t sni_middle(const d2k_trigger *tr, size_t n)
{
    size_t mid = n / 2;
    if (tr->sni_len > 1 && tr->sni_off > 0) {
        mid = (size_t)tr->sni_off + (size_t)tr->sni_len / 2;
    }
    if (mid < 2) {
        mid = 2;
    }
    if (mid >= n) {
        mid = n - 1;
    }
    return mid;
}

/* Перенос ветвей d2k_raw_probe_poison_family один к одному: номера, байты,
 * порча и паузы те же, что слал зонд до выноса (raw.c, 09.10.2026). */
int d2k_poison_sends(const d2k_trigger *tr, const d2k_poison *p,
                     uint8_t *fake, size_t fake_cap, uint8_t *seg, size_t seg_cap,
                     d2k_sends *out)
{
    size_t n = tr->len;
    int pause = 0; /* пауза перед следующей посылкой */
    int i, reps = p->repeats < 1 ? 1 : p->repeats;

    memset(out, 0, sizeof(*out));
    out->stream_len = (int)n;
    if (n == 0) {
        return -1;
    }

    /* ШАГ 1: подделка в ту же область, что займёт правда, длиной 2×n. */
    if (strcmp(p->name, "none") != 0 && d2k_poison_has_fake(p)) {
        size_t flen = n * 2;
        if (flen > fake_cap) {
            flen = fake_cap;
        }
        memset(fake, 0x0f, flen);
        if (p->decoy && p->decoy_len > 0) {
            memcpy(fake, p->decoy, p->decoy_len < flen ? p->decoy_len : flen);
        }
        for (i = 0; i < reps; i++) {
            if (push(out, D2K_SEND_FAKE, 0, fake, flen, p,
                     i > 0 && p->gap_ms > 0 ? p->gap_ms : 0) != 0) {
                return -1;
            }
        }
        pause = 15;
    }

    /* ШАГ 2: настоящие данные. */
    if (p->syn_data) {
        if (push(out, D2K_SEND_PAYLOAD, 0, tr->payload, n, NULL, pause) != 0) {
            return -1;
        }
        out->v[out->n - 1].syn = 1;
    } else if (p->oob) {
        static const uint8_t urgb[1] = {0x0f};
        size_t mid = n / 2;
        if (tr->sni_len > 1 && tr->sni_off > 0) {
            mid = (size_t)tr->sni_off + (size_t)tr->sni_len / 2;
        }
        if (mid < 1 || mid >= n) {
            mid = n / 2;
        }
        if (push(out, D2K_SEND_PAYLOAD, 0, tr->payload, mid, NULL, pause) != 0 ||
            push(out, D2K_SEND_URG, (int64_t)mid, urgb, 1, NULL, 0) != 0 ||
            push(out, D2K_SEND_PAYLOAD, (int64_t)mid + 1, tr->payload + mid, n - mid, NULL, 0) != 0) {
            return -1;
        }
        out->stream_len = (int)n + 1;
    } else if (p->fake_between) {
        size_t mid = 1, flen;
        d2k_poison fp;
        if (tr->sni_len > 1 && tr->sni_off > 0) {
            mid = (size_t)tr->sni_off;
        }
        if (mid >= n) {
            mid = 1;
        }
        if (push(out, D2K_SEND_PAYLOAD, 0, tr->payload, mid, NULL, pause) != 0) {
            return -1;
        }
        flen = n - mid;
        if (flen > fake_cap) {
            flen = fake_cap;
        }
        memset(fake, 0x0f, flen);
        memset(&fp, 0, sizeof(fp));
        fp.badsum = p->badsum;
        fp.ttl = p->ttl;
        for (i = 0; i < reps; i++) {
            if (push(out, D2K_SEND_FAKE, (int64_t)mid, fake, flen, &fp, 0) != 0) {
                return -1;
            }
        }
        if (push(out, D2K_SEND_PAYLOAD, (int64_t)mid, tr->payload + mid, n - mid, NULL, 12) != 0) {
            return -1;
        }
    } else if (p->disorder_pos > 0) {
        size_t split = (size_t)p->disorder_pos;
        if (split >= n) {
            return -1;
        }
        if (push(out, D2K_SEND_PAYLOAD, (int64_t)split, tr->payload + split, n - split, NULL, pause) != 0 ||
            push(out, D2K_SEND_PAYLOAD, 0, tr->payload, split, NULL, 0) != 0) {
            return -1;
        }
    } else if (p->seqovl > 0 && p->disorder) {
        size_t mid = sni_middle(tr, n);
        size_t ov = (size_t)p->seqovl;
        if (ov + 1 > seg_cap) {
            ov = seg_cap - 1;
        }
        memset(seg, 0x0f, ov);
        if (p->decoy && p->decoy_len > 0) {
            memcpy(seg, p->decoy, p->decoy_len < ov ? p->decoy_len : ov);
        }
        seg[ov] = tr->payload[0];
        /* Хвост первым, голова последней и внахлёст слева. */
        if (push(out, D2K_SEND_PAYLOAD, (int64_t)mid, tr->payload + mid, n - mid, NULL, pause) != 0 ||
            push(out, D2K_SEND_PAYLOAD, 1, tr->payload + 1, mid - 1, NULL, 12) != 0 ||
            push(out, D2K_SEND_PAYLOAD, -(int64_t)ov, seg, ov + 1, NULL, 12) != 0) {
            return -1;
        }
    } else if (p->seqovl > 0) {
        /* Внахлёст слева ОДНИМ сегментом: base-N, первые N байт — приманка. */
        size_t ov = (size_t)p->seqovl;
        if (ov + n > seg_cap) {
            ov = seg_cap - n;
        }
        memset(seg, 0x0f, ov);
        if (p->decoy && p->decoy_len > 0) {
            memcpy(seg, p->decoy, p->decoy_len < ov ? p->decoy_len : ov);
        }
        memcpy(seg + ov, tr->payload, n);
        if (push(out, D2K_SEND_PAYLOAD, -(int64_t)ov, seg, ov + n, NULL, pause) != 0) {
            return -1;
        }
    } else if (p->disorder) {
        /* Три куска по середине имени, первый байт — последним. */
        size_t mid = sni_middle(tr, n);
        if (push(out, D2K_SEND_PAYLOAD, (int64_t)mid, tr->payload + mid, n - mid, NULL, pause) != 0 ||
            push(out, D2K_SEND_PAYLOAD, 1, tr->payload + 1, mid - 1, NULL, 12) != 0 ||
            push(out, D2K_SEND_PAYLOAD, 0, tr->payload, 1, NULL, 12) != 0) {
            return -1;
        }
        out->tail_ms = 12;
    } else if (p->split_pos > 0) {
        /* Разрез НАСТОЯЩЕЙ нагрузки прямым порядком: голова [0,split) первой,
         * хвост [split,n) следом, после серии фальшивок под меткой времени.
         * Так режет настоящее приветствие семейство C (split payload_start +2)
         * — ровно рабочий plan-680fbe00. Отличие от disorder_pos — порядок:
         * там хвост уходит ПЕРВЫМ (обратный), здесь голова (прямой). */
        size_t sp = (size_t)p->split_pos;
        if (sp >= n) {
            return -1;
        }
        if (push(out, D2K_SEND_PAYLOAD, 0, tr->payload, sp, NULL, pause) != 0 ||
            push(out, D2K_SEND_PAYLOAD, (int64_t)sp, tr->payload + sp, n - sp, NULL, 0) != 0) {
            return -1;
        }
    } else {
        if (push(out, D2K_SEND_PAYLOAD, 0, tr->payload, n, NULL, pause) != 0) {
            return -1;
        }
    }
    return 0;
}

#define POISON_CAP 128
static d2k_poison g_poisons[POISON_CAP];
static int g_npoisons;
static pthread_once_t g_poisons_once = PTHREAD_ONCE_INIT;

static d2k_poison *add(const char *fmt, ...)
{
    va_list ap;
    d2k_poison *p;
    if (g_npoisons >= POISON_CAP) {
        return &g_poisons[POISON_CAP - 1];
    }
    p = &g_poisons[g_npoisons++];
    memset(p, 0, sizeof(*p));
    va_start(ap, fmt);
    vsnprintf(p->name, sizeof(p->name), fmt, ap);
    va_end(ap);
    return p;
}

int d2k_poison_same(const d2k_poison *x, const d2k_poison *y)
{
    d2k_poison a = *x, b = *y;
    memset(a.name, 0, sizeof a.name);
    memset(b.name, 0, sizeof b.name);
    if (a.repeats <= 1) { a.repeats = 1; }
    if (b.repeats <= 1) { b.repeats = 1; }
    return memcmp(&a, &b, sizeof a) == 0;
}

/* Та же гипотеза по всем параметрам, кроме имени, уже есть в списке. */
static int already_listed(const d2k_poison *p)
{
    int k;
    for (k = 0; k < g_npoisons; k++) {
        const d2k_poison *q = &g_poisons[k];
        if (q == p) { continue; }
        if (d2k_poison_same(q, p)) { return 1; }
    }
    return 0;
}

static void init_poisons(void)
{
    static const int rr[3] = {7, 4, 2};
    static const int ov3[3] = {1, 336, 681};
    static const int ovn[7] = {2, 4, 8, 16, 64, 336, 681};
    static const int gaps[4] = {0, 20, 80, 300};
    static const int reps[4] = {2, 3, 4, 7};
    static const int ttls[8] = {62, 60, 58, 55, 50, 40, 20, 8};
    static const int dttls[3] = {62, 58, 50};
    d2k_poison *p;
    int i, j;

    /* ПОРЯДОК — ЭТО СТОИМОСТЬ. Перекрытие в один байт (facebook), разнесённые
     * дубликаты (YouTube, googlevideo) и плотная семёрка — первыми. */
    p = add("seqovl-1");           p->seqovl = 1;
    p = add("badsum-x2-g20");      p->badsum = 1; p->repeats = 2; p->gap_ms = 20;
    p = add("badsum-x2-g80");      p->badsum = 1; p->repeats = 2; p->gap_ms = 80;
    p = add("badsum-x7");          p->badsum = 1; p->repeats = 7;
    p = add("disorder");           p->disorder = 1;
    p = add("disorder-pos2");      p->disorder = 1; p->disorder_pos = 2;
    p = add("badsum");             p->badsum = 1;
    p = add("md5");                p->md5 = 1;
    p = add("seq-out-of-window");  p->seq_shift = -66000;

    /* ПРИМИТИВЫ, КОТОРЫХ НЕ БЫЛО: самостоятельные механизмы, а не варианты
     * уже покрытых. Флаги обязаны стоять — без них это пустые гипотезы с
     * говорящими именами. */
    p = add("syndata");            p->syn_data = 1;
    p = add("oob");                p->oob = 1;

    /* ОДИН вариант fakedsplit, а не четыре: отправитель в ветке fakeBetween
     * не читает ни seqovl, ни disorder, и варианты были побайтно теми же
     * пакетами. */
    p = add("fakedsplit");         p->fake_between = 1; p->badsum = 1;
    p = add("fakedsplit-x7");      p->fake_between = 1; p->badsum = 1; p->repeats = 7;

    /* ТОЧНАЯ КОПИЯ БОЕВОГО ПЛЕЧА 1: копии фальшивки отдельной посылкой, затем
     * перекрытие слева длиной в целое приветствие. Собрано по дампу. */
    for (i = 0; i < 3; i++) {
        p = add("fake-x%d+seqovl-hello", rr[i]);
        p->badsum = 1; p->repeats = rr[i]; p->seqovl_exact = 1; p->decoy_hello = 1;
        p = add("fake-x%d+seqovl-681", rr[i]);
        p->badsum = 1; p->repeats = rr[i]; p->seqovl = 681; p->decoy_hello = 1;
        p = add("fake-x%d+ttl62+seqovl-hello", rr[i]);
        p->badsum = 1; p->ttl = 62; p->repeats = rr[i]; p->seqovl_exact = 1; p->decoy_hello = 1;
    }

    p = add("seqovl-hello");                    p->seqovl_exact = 1; p->decoy_hello = 1;
    p = add("seqovl-hello+disorder");           p->seqovl_exact = 1; p->decoy_hello = 1; p->disorder = 1;
    p = add("seqovl-hello+disorder+badsum");    p->seqovl_exact = 1; p->decoy_hello = 1; p->disorder = 1; p->badsum = 1;

    /* ТРОЙНЫЕ СВЯЗКИ: фальшивка + перекрытие + сбитый порядок одновременно. */
    for (i = 0; i < 3; i++) {
        p = add("seqovl-%d+disorder", ov3[i]);        p->seqovl = ov3[i]; p->disorder = 1;
        p = add("seqovl-%d+disorder+hello", ov3[i]);  p->seqovl = ov3[i]; p->disorder = 1; p->decoy_hello = 1;
        p = add("seqovl-%d+disorder+badsum", ov3[i]); p->seqovl = ov3[i]; p->disorder = 1; p->badsum = 1;
    }

    for (i = 0; i < 7; i++) {
        p = add("seqovl-%d", ovn[i]);        p->seqovl = ovn[i];
        p = add("seqovl-%d+hello", ovn[i]);  p->seqovl = ovn[i]; p->decoy_hello = 1;
    }

    /* Дубликаты: число копий × пауза. Обе оси нужны — порог 7 оказался
     * артефактом нулевой паузы, при 20 мс хватает двух. */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            p = add("badsum-x%d-g%d", reps[j], gaps[i]);
            p->badsum = 1; p->repeats = reps[j]; p->gap_ms = gaps[i];
            /* УЖЕ СПРОШЕНО ВЫШЕ (задача 49): badsum-x2-g20, badsum-x2-g80 и
             * badsum-x7 (= x7-g0) стоят в голове списка, где им и место по
             * цене. У донора они спрашивались второй раз — при единогласии
             * исход повтора тот же, это три лишних зонда. Решение владельца
             * 03.10: трассу донора здесь не повторяем. */
            if (already_listed(p)) { g_npoisons--; }
        }
    }

    /* TTL сверху вниз: фальшивка должна пройти почти весь путь и умереть
     * перед сервером, а не сдохнуть у первого маршрутизатора. */
    for (i = 0; i < 8; i++) {
        p = add("ttl-%d", ttls[i]);         p->ttl = ttls[i];
        p = add("badsum+ttl-%d", ttls[i]);  p->badsum = 1; p->ttl = ttls[i];
    }

    p = add("disorder+badsum");        p->disorder = 1; p->badsum = 1;
    p = add("disorder+badsum+hello");  p->disorder = 1; p->badsum = 1; p->decoy_hello = 1;
    for (i = 0; i < 3; i++) {
        p = add("disorder+badsum+ttl-%d", dttls[i]);
        p->disorder = 1; p->badsum = 1; p->ttl = dttls[i];
    }

    p = add("badsum+ts");    p->badsum = 1; p->tcp_ts = 1;
    p = add("badsum+ipid");  p->badsum = 1; p->ip_id_zero = 1;
    p = add("badsum+hello"); p->badsum = 1; p->decoy_hello = 1;

}

const d2k_poison *d2k_poisons(int *n)
{
    /* Publish only a complete immutable list. An in-progress count is not
     * an initialization flag when several scheduler workers enter here. */
    pthread_once(&g_poisons_once, init_poisons);
    *n = g_npoisons;
    return g_poisons;
}

/* notePropsHit/notePropsMiss переводят исход зонда в свойство коробки.
 * Именно здесь перебор перестаёт быть перебором: каждая попытка что-то
 * РАССКАЗЫВАЕТ о коробке, даже когда не срабатывает. */
void d2k_note_props_hit(d2k_dprops *pr, const d2k_poison *p)
{
    if (p->badsum) {
        pr->validates_checksum = D2K_TRI_FALSE; /* съела битую сумму */
    } else if (p->ttl > 0) {
        pr->hop_ttl = p->ttl;
    } else if (p->disorder) {
        pr->tolerates_reorder = D2K_TRI_FALSE;
    } else if (p->seqovl > 0) {
        pr->tolerates_left_overlap = D2K_TRI_FALSE;
    }
    if (p->decoy_hello) {
        pr->parses_l7 = D2K_TRI_TRUE; /* набивку не взяла, приветствие взяла */
    }
}

/* Промах доказывает немного. Сюда попадают только выводы, где он однозначен:
 * приём НЕ ломает коробку, значит она к нему терпима.
 *
 * ЧЕГО ЗДЕСЬ НЕТ: промах badsum-зонда НЕ пишет ValidatesChecksum = true. Это
 * вывод из тишины, запрещённый нормой пакета, и тот же исход в hit даёт
 * false — один прогон мог выдать оба вывода. */
void d2k_note_props_miss(d2k_dprops *pr, const d2k_poison *p)
{
    if (p->disorder) {
        pr->tolerates_reorder = D2K_TRI_TRUE;
    } else if (p->seqovl > 0 && !p->decoy_hello) {
        pr->tolerates_left_overlap = D2K_TRI_TRUE;
    }
}

/* strategyForPoison переводит найденную разницу в термины nfqws2. */
void d2k_strategy_for_poison(const d2k_poison *p, char *out, size_t cap)
{
    char head[512];
    char f[512];
    char ov[512];
    char st[768];

    out[0] = '\0';

    if (p->syn_data) {
        snprintf(out, cap, "--lua-desync=syndata:payload=tls_client_hello:dir=out");
        return;
    }
    if (p->oob) {
        snprintf(out, cap, "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:oob");
        return;
    }
    if (p->fake_between) {
        snprintf(st, sizeof(st), "--lua-desync=fakedsplit:payload=tls_client_hello:dir=out:pos=1");
        if (p->badsum) {
            strncat(st, ":badsum", sizeof(st) - strlen(st) - 1);
        }
        if (p->repeats > 1) {
            char t[32];
            snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
            strncat(st, t, sizeof(st) - strlen(st) - 1);
        }
        snprintf(out, cap, "%s", st);
        return;
    }
    if (d2k_poison_has_fake(p) && (p->seqovl > 0 || p->seqovl_exact)) {
        char t[64];
        snprintf(f, sizeof(f),
                 "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls"
                 ":tls_mod=rnd,dupsid,sni=www.google.com");
        if (p->badsum) {
            strncat(f, ":badsum", sizeof(f) - strlen(f) - 1);
        }
        if (p->ttl > 0) {
            snprintf(t, sizeof(t), ":ip_ttl=%d", p->ttl);
            strncat(f, t, sizeof(f) - strlen(f) - 1);
        }
        if (p->repeats > 1) {
            snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
            strncat(f, t, sizeof(f) - strlen(f) - 1);
        }
        /* Длину перекрытия печатаем ИЗМЕРЕННУЮ, а не зашитую: seqovl-1 меряет
         * перекрытие в ОДИН байт, и печатать ей 681 значит выдать другой приём. */
        if (p->seqovl_exact) {
            snprintf(ov, sizeof(ov),
                     " --lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=681"
                     ":seqovl_pattern=tls_clienthello_www_google_com");
        } else {
            snprintf(ov, sizeof(ov),
                     " --lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=%d",
                     p->seqovl);
            if (p->decoy_hello) {
                strncat(ov, ":seqovl_pattern=tls_clienthello_www_google_com",
                        sizeof(ov) - strlen(ov) - 1);
            }
        }
        if (p->disorder) {
            strncat(ov, " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
                    sizeof(ov) - strlen(ov) - 1);
        }
        snprintf(out, cap, "%s%s", f, ov);
        return;
    }
    if (p->seqovl_exact) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=681"
                 ":seqovl_pattern=tls_clienthello_www_google_com");
        if (p->disorder) {
            strncat(st, " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
                    sizeof(st) - strlen(st) - 1);
        }
        snprintf(out, cap, "%s", st);
        return;
    }
    if (p->seqovl > 0 && p->disorder) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=%d",
                 p->seqovl);
        if (p->decoy_hello) {
            strncat(st, ":seqovl_pattern=tls_clienthello_www_google_com",
                    sizeof(st) - strlen(st) - 1);
        }
        strncat(st, " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
                sizeof(st) - strlen(st) - 1);
        snprintf(out, cap, "%s", st);
        return;
    }
    if (p->disorder_pos > 0) {
        snprintf(out, cap,
                 "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=%d",
                 p->disorder_pos);
        return;
    }
    if (p->disorder) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld");
        if (d2k_poison_has_fake(p)) {
            char t[64];
            /* Связка: сперва фальшивка, следом настоящие сегменты вразнобой. */
            snprintf(f, sizeof(f),
                     "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls");
            if (p->decoy_hello) {
                strncat(f, ":tls_mod=rnd,dupsid,sni=www.google.com", sizeof(f) - strlen(f) - 1);
            }
            if (p->badsum) {
                strncat(f, ":badsum", sizeof(f) - strlen(f) - 1);
            }
            if (p->ttl > 0) {
                snprintf(t, sizeof(t), ":ip_ttl=%d", p->ttl);
                strncat(f, t, sizeof(f) - strlen(f) - 1);
            }
            if (p->repeats > 1) {
                snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
                strncat(f, t, sizeof(f) - strlen(f) - 1);
            }
            snprintf(out, cap, "%s %s", f, st);
            return;
        }
        snprintf(out, cap, "%s", st);
        return;
    }
    if (p->seqovl > 0) {
        snprintf(st, sizeof(st),
                 "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=%d",
                 p->seqovl);
        if (p->decoy_hello) {
            strncat(st, ":seqovl_pattern=tls_clienthello_www_google_com",
                    sizeof(st) - strlen(st) - 1);
        }
        snprintf(out, cap, "%s", st);
        return;
    }

    snprintf(head, sizeof(head),
             "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls");
    /* Число копий печатается ЗДЕСЬ, до всех ранних возвратов ветки: без этого
     * семнадцать гипотез badsum-x{N}-g{G} выдавали ту же строку, что одиночная
     * badsum, и инструмент отдавал плечо с одной фальшивкой. */
    if (p->repeats > 1) {
        char t[32];
        snprintf(t, sizeof(t), ":repeats=%d", p->repeats);
        strncat(head, t, sizeof(head) - strlen(head) - 1);
    }
    if (p->tcp_ts) {
        strncat(head, ":tcp_ts=-1000", sizeof(head) - strlen(head) - 1);
    }
    if (p->ip_id_zero) {
        strncat(head, ":ip_id=zero", sizeof(head) - strlen(head) - 1);
    }
    if (p->badsum && p->ttl > 0) {
        snprintf(out, cap, "%s:badsum:ip_ttl=%d", head, p->ttl);
        return;
    }
    if (p->decoy_hello) {
        /* Приманкой служит приветствие с чужим именем — ровно то, что даёт
         * tls_mod=sni=... в боевых плечах. */
        strncat(head, ":tls_mod=rnd,dupsid,sni=www.google.com", sizeof(head) - strlen(head) - 1);
    }
    if (p->badsum) {
        snprintf(out, cap, "%s:badsum", head);
    } else if (p->md5) {
        snprintf(out, cap, "%s:tcp_md5", head);
    } else if (p->seq_shift != 0) {
        snprintf(out, cap, "%s:tcp_seq=%ld", head, (long)p->seq_shift);
    } else if (p->ttl > 0) {
        snprintf(out, cap, "%s:ip_ttl=%d", head, p->ttl);
    }
}

/* strategyFor — как записать найденное в термины nfqws2. */
void d2k_strategy_for(int pos, char *out, size_t cap)
{
    snprintf(out, cap, "--lua-desync=multisplit:payload=unknown:dir=out:pos=%d", pos);
}
