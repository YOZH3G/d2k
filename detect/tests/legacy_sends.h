/* Frozen pre-unification schedule. Test oracle only, never linked into runtime.
 * Family C intentionally changed by the 10.10 field specification; its
 * authoritative oracle is the RX program plus the raw/runtime packet test. */
#define D2K_SEND_FAKE    0  /* подделка: сервер выбросит, коробка возьмёт */
#define D2K_SEND_PAYLOAD 1  /* настоящие байты приветствия */
#define D2K_SEND_URG     2  /* посторонний байт со срочным указателем */
#define D2K_SEND_MAX     16
typedef struct {
    int            kind;     /* D2K_SEND_* */
    int            syn;      /* флаг SYN поверх готового соединения (syndata) */
    int64_t        seq_off;  /* номер относительно начала приветствия, до seq_shift */
    const uint8_t *bytes;
    size_t         len;
    d2k_poison     poison;   /* порча посылки; у настоящих байтов — нулевая */
    int            delay_ms; /* пауза ПЕРЕД посылкой */
} d2k_send;
typedef struct {
    d2k_send v[D2K_SEND_MAX];
    size_t   n;
    int      tail_ms;    /* пауза после последней посылки, до чтения ответа */
    int      stream_len; /* на сколько байт сдвинулся поток (oob: +1) */
} d2k_sends;
/* fake и seg — буферы вызывающего: в них собираются подделка и сегмент
 * перекрытия, посылки ссылаются на них и на tr->payload. 0 — список готов,
 * -1 — не уместилось. */
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
static int d2k_poison_sends(const d2k_trigger *tr, const d2k_poison *p,
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
