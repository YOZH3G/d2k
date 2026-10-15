/* quicsnap.c — снимок QUIC-приветствия клиента из нескольких датаграмм.
 * Зачем, формат и контракты — в шапке d2k_quicsnap.h. */
#include <string.h>

#include "d2k_quicsnap.h"
#include "d2k_quic.h"
#include "d2k_quicwire.h"

#define QSN_HDR 4 /* 'Q','S','N', count */
/* ClientHello с ML-KEM около 2 КБ; буфер общий для сборки и формы. */
#define QSN_CH_MAX 8192

int d2k_qsnap_is(const uint8_t *p, size_t n) {
    return p && n >= QSN_HDR && p[0] == 'Q' && p[1] == 'S' && p[2] == 'N';
}

int d2k_qsnap_parse(const uint8_t *p, size_t n, d2k_qsnap *out) {
    if (!out || !d2k_qsnap_is(p, n)) {
        return -1;
    }
    size_t count = p[3];
    if (count == 0 || count > D2K_QSNAP_MAX_DGRAMS) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    size_t off = QSN_HDR;
    for (size_t i = 0; i < count; i++) {
        if (off + 2 > n) {
            return -1;
        }
        size_t len = (size_t)p[off] << 8 | p[off + 1];
        off += 2;
        if (len == 0 || len > D2K_QW_MAX_DGRAM || off + len > n) {
            return -1;
        }
        out->dg[i] = p + off;
        out->len[i] = len;
        off += len;
    }
    /* Хвост за последней датаграммой — не та пачка, которую слал клиент:
       разбирать её наполовину значило бы мерить неизвестно чем. */
    if (off != n) {
        return -1;
    }
    out->n = count;
    return 0;
}

size_t d2k_qsnap_pack(const uint8_t *const *dg, const size_t *len, size_t n,
                      uint8_t *out, size_t cap) {
    if (!dg || !len || !out || n == 0 || n > D2K_QSNAP_MAX_DGRAMS) {
        return 0;
    }
    size_t need = QSN_HDR;
    for (size_t i = 0; i < n; i++) {
        if (!dg[i] || len[i] == 0 || len[i] > D2K_QW_MAX_DGRAM) {
            return 0;
        }
        need += 2 + len[i];
    }
    if (need > cap) {
        return 0;
    }
    out[0] = 'Q'; out[1] = 'S'; out[2] = 'N'; out[3] = (uint8_t)n;
    size_t off = QSN_HDR;
    for (size_t i = 0; i < n; i++) {
        out[off++] = (uint8_t)(len[i] >> 8);
        out[off++] = (uint8_t)len[i];
        memcpy(out + off, dg[i], len[i]);
        off += len[i];
    }
    return off;
}

int d2k_qsnap_client_hello(const d2k_qsnap *s, uint8_t *out, size_t cap, size_t *out_len) {
    if (!s || s->n == 0 || s->n > D2K_QSNAP_MAX_DGRAMS) {
        return -1;
    }
    return d2k_quic_dgrams_hello(s->dg, s->len, s->n, out, cap, out_len);
}

int d2k_qsnap_sni(const d2k_qsnap *s, char *out, size_t cap) {
    uint8_t ch[QSN_CH_MAX];
    size_t chl = 0;
    if (d2k_qsnap_client_hello(s, ch, sizeof ch, &chl) != 0) {
        return -1;
    }
    return d2k_quic_hello_name(ch, chl, out, cap);
}

int d2k_qsnap_form(const d2k_qsnap *s, d2k_quic_form *f) {
    uint8_t ch[QSN_CH_MAX];
    size_t chl = 0;
    if (!f || d2k_qsnap_client_hello(s, ch, sizeof ch, &chl) != 0) {
        return -1;
    }
    if (s->len[0] > 0xffffu || chl > 0xffffu) {
        return -1;
    }
    f->n = (uint8_t)s->n;
    f->dgram_len = (uint16_t)s->len[0];
    f->ch_len = (uint16_t)chl;
    return 0;
}
