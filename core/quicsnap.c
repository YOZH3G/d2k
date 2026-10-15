/* quicsnap.c — снимок QUIC-приветствия клиента из нескольких датаграмм.
 * Зачем, формат и контракты — в шапке d2k_quicsnap.h. */
#include <string.h>

#include "d2k_quicsnap.h"
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "d2k_tls13core.h"

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

/* --- перезапечатка пачки под новый идентификатор -------------------------- */

/* Один пакет пачки: открыть старыми ключами, собрать заголовок с новым DCID,
   запечатать новыми. Всё остальное — из снимка: номер пакета и его длина,
   SCID, токен, фиксированный бит, итоговый размер датаграммы.

   Длина номера пакета берётся ИЗ СНИМКА, а не считается заново: клиент
   выбирает её сам (RFC 9000 §17.1), и пересчёт укоротил бы датаграмму — то
   есть изменил бы форму, ради сохранности которой всё это и делается.
   Считается вычитанием: поле Length покрывает номер, тело и тег AEAD. */
static int reseal_one(const uint8_t *in, size_t n,
                      const d2k_qw_keys *old_k, const d2k_qw_keys *new_k,
                      const uint8_t *dcid, size_t dcid_len,
                      uint8_t *out, size_t cap, size_t *out_len) {
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(in, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL || h.packet_len != n) {
        return -1;
    }
    uint8_t plain[D2K_QW_MAX_DGRAM];
    size_t plain_len = 0;
    uint64_t pn = 0;
    if (n > sizeof plain || d2k_qw_open(old_k, &h, in, 0, plain, &plain_len, &pn) != 0) {
        return -1;
    }
    if (h.length_claimed < plain_len + 16) {
        return -1;
    }
    size_t pn_len = h.length_claimed - plain_len - 16;
    if (pn_len < 1 || pn_len > 4) {
        return -1;
    }
    uint8_t pkt[D2K_QW_MAX_DGRAM];
    size_t hlen = h.token_len
        ? d2k_qw_long_hdr_token(pkt, sizeof pkt, h.version, D2K_QW_LT_INITIAL,
                                dcid, dcid_len, in + h.scid_off, h.scid_len,
                                in + h.token_off, h.token_len, pn_len, plain_len)
        : d2k_qw_long_hdr(pkt, sizeof pkt, h.version, D2K_QW_LT_INITIAL,
                          dcid, dcid_len, in + h.scid_off, h.scid_len,
                          pn_len, plain_len);
    if (hlen == 0) {
        return -1;
    }
    /* ФИКСИРОВАННЫЙ БИТ — ИЗ СНИМКА. Сборщик заголовка ставит его всегда (RFC
       9000 §17.2), а клиент вправе его гасить (RFC 9287), и защита заголовка
       его не маскирует. Пересобрать «как положено» значило бы изменить
       форму — и вопрос про погашенный бит никогда бы не подтвердился. */
    pkt[0] = (uint8_t)((pkt[0] & (uint8_t)~0x40u) | (in[0] & 0x40u));
    size_t made = d2k_qw_seal(new_k, 1, pkt, hlen, pn, pn_len, plain, plain_len,
                              pkt, sizeof pkt);
    /* Длина обязана совпасть со снимком: добивка уже внутри расшифрованного
       содержимого, и другая длина значила бы, что ушло что-то ещё, кроме
       идентификатора. */
    if (made == 0 || made != n || made > cap) {
        return -1;
    }
    memcpy(out, pkt, made);
    *out_len = made;
    return 0;
}

int d2k_qsnap_recid(const d2k_qsnap *s, uint8_t *out, size_t cap, size_t *out_len) {
    if (!s || !out || !out_len || s->n == 0 || s->n > D2K_QSNAP_MAX_DGRAMS) {
        return -1;
    }
    d2k_qw_hdr first;
    if (d2k_qw_hdr_parse(s->dg[0], s->len[0], 0, &first) != 0 || !first.long_hdr ||
        first.type != D2K_QW_LT_INITIAL) {
        return -1;
    }
    /* Соль у каждой версии своя (RFC 9001 §5.2, RFC 9369 §3.3.1): версию, для
       которой её нет, перезапечатать нечем. */
    if (first.version != D2K_QW_V1 && first.version != D2K_QW_V2) {
        return -1;
    }

    /* Старые ключи — из DCID ПЕРВОЙ датаграммы: весь полёт идёт под ним. */
    uint8_t sec[32];
    d2k_qw_keys old_k, new_k;
    if (d2k_qw_initial_secret(first.version, s->dg[0] + first.dcid_off, first.dcid_len,
                              D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(first.version, sec, &old_k) != 0) {
        return -1;
    }
    /* Новый DCID — ТОЙ ЖЕ ДЛИНЫ и ОДИН на всю пачку: длина тоже форма, а два
       разных идентификатора сервер принял бы за два соединения с половиной
       приветствия каждое. */
    uint8_t dcid[D2K_QW_CID_MAX];
    size_t dcid_len = (first.dcid_len >= 8 && first.dcid_len <= sizeof dcid)
                      ? first.dcid_len : 8;
    if (d2k_t13_random(dcid, dcid_len) != 0 ||
        d2k_qw_initial_secret(first.version, dcid, dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(first.version, sec, &new_k) != 0) {
        return -1;
    }

    uint8_t made[D2K_QSNAP_MAX_DGRAMS][D2K_QW_MAX_DGRAM];
    const uint8_t *dg[D2K_QSNAP_MAX_DGRAMS];
    size_t len[D2K_QSNAP_MAX_DGRAMS];
    for (size_t i = 0; i < s->n; i++) {
        d2k_qw_hdr h;
        /* Чужая датаграмма в пачке (Retry, другой поток в кольце датапата) —
           отказ целиком: склеенный из двух полётов снимок не слал никто. */
        if (d2k_qw_hdr_parse(s->dg[i], s->len[i], 0, &h) != 0 || !h.long_hdr ||
            h.version != first.version || h.dcid_len != first.dcid_len ||
            memcmp(s->dg[i] + h.dcid_off, s->dg[0] + first.dcid_off, first.dcid_len) != 0) {
            return -1;
        }
        if (reseal_one(s->dg[i], s->len[i], &old_k, &new_k, dcid, dcid_len,
                       made[i], sizeof made[i], &len[i]) != 0) {
            return -1;
        }
        dg[i] = made[i];
    }
    size_t packed = d2k_qsnap_pack(dg, len, s->n, out, cap);
    if (packed == 0) {
        return -1;
    }
    *out_len = packed;
    return 0;
}
