/* test_quic_pq.h — клиентский Initial размера Chrome с постквантовым
 * key_share: ClientHello не помещается в одну датаграмму, и server_name
 * (перестановка расширений Chrome) лежит во ВТОРОЙ. Задача 40, круг 1:
 * исполнитель разреза CRYPTO обязан отказать на первой датаграмме — имени
 * в ней нет, а такой разрез никто не мерил.
 *
 * Только для тестов: собирается модулем провода (d2k_quicwire.h) с общим
 * DCID, номера пакетов 0 и 1, каждая датаграмма добита до 1200 байт. */
#ifndef D2K_TEST_QUIC_PQ_H
#define D2K_TEST_QUIC_PQ_H

#include <stdint.h>
#include <string.h>
#include "d2k_quicwire.h"

#define D2K_TEST_PQ_CUT 1000u /* где кончается CRYPTO первой датаграммы */

static size_t d2k_test_pq_hello(uint8_t *ch, size_t cap, const char *name) {
    size_t m = strlen(name), n = 0;
    size_t ks = 1220; /* key_share X25519MLKEM768: 1216 байт ключа + заголовки */
    size_t sni_ext = 2 + 2 + 2 + 1 + 2 + m;
    size_t exts = 4 + ks + sni_ext;
    size_t body = 2 + 32 + 1 + 4 + 2 + 2 + exts;
    if (cap < 4 + body) return 0;
    ch[n++] = 0x01;
    ch[n++] = (uint8_t)(body >> 16); ch[n++] = (uint8_t)(body >> 8); ch[n++] = (uint8_t)body;
    ch[n++] = 0x03; ch[n++] = 0x03;
    for (int i = 0; i < 32; i++) ch[n++] = (uint8_t)(0x40 + i);
    ch[n++] = 0;                                        /* session id */
    ch[n++] = 0; ch[n++] = 2; ch[n++] = 0x13; ch[n++] = 0x01; /* cipher suites */
    ch[n++] = 1; ch[n++] = 0;                           /* compression */
    ch[n++] = (uint8_t)(exts >> 8); ch[n++] = (uint8_t)exts;
    ch[n++] = 0x00; ch[n++] = 0x33;                     /* key_share — первым */
    ch[n++] = (uint8_t)(ks >> 8); ch[n++] = (uint8_t)ks;
    memset(ch + n, 0x5a, ks); n += ks;
    ch[n++] = 0x00; ch[n++] = 0x00;                     /* server_name — последним */
    ch[n++] = (uint8_t)((sni_ext - 4) >> 8); ch[n++] = (uint8_t)(sni_ext - 4);
    ch[n++] = (uint8_t)((m + 3) >> 8); ch[n++] = (uint8_t)(m + 3);
    ch[n++] = 0;
    ch[n++] = (uint8_t)(m >> 8); ch[n++] = (uint8_t)m;
    memcpy(ch + n, name, m); n += m;
    return n;
}

/* Одна Initial-датаграмма с кадром CRYPTO [off, off+len), добитая до 1200. */
static size_t d2k_test_pq_dgram(const uint8_t dcid[8], uint64_t pn, uint64_t off,
                                const uint8_t *data, size_t len, uint8_t *out, size_t cap) {
    uint8_t sec[32], body[1200], hdr[64];
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(D2K_QW_V1, dcid, 8, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, sec, &k) != 0) return 0;
    size_t b = 0;
    memset(body, 0, sizeof body);
    body[b++] = 0x06;
    b += d2k_qw_varint_write(body + b, sizeof body - b, off);
    b += d2k_qw_varint_write(body + b, sizeof body - b, len);
    if (b + len > sizeof body) return 0;
    memcpy(body + b, data, len);
    b += len;
    /* 1 + 4 + 1 + 8 (DCID) + 1 + 8 (SCID) + 1 (токен) + 2 (длина) + 4 (номер)
       + 16 (тег) = 46 байт сверх тела. */
    size_t plain = 1200 - 46;
    if (b > plain) return 0;
    static const uint8_t scid[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    size_t hl = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL, dcid, 8,
                                scid, 8, 4, plain);
    if (!hl) return 0;
    return d2k_qw_seal(&k, 1, hdr, hl, pn, 4, body, plain, out, cap);
}

/* Обе датаграммы: первая без имени, вторая с ним. 0 — собрано. */
static int d2k_test_pq_initials(const char *name, uint8_t *d1, size_t *l1,
                                uint8_t *d2, size_t *l2) {
    static const uint8_t dcid[8] = {0xd1, 0x2a, 3, 4, 5, 6, 7, 8};
    uint8_t ch[2048];
    size_t chl = d2k_test_pq_hello(ch, sizeof ch, name);
    if (chl <= D2K_TEST_PQ_CUT) return -1;
    *l1 = d2k_test_pq_dgram(dcid, 0, 0, ch, D2K_TEST_PQ_CUT, d1, 1500);
    *l2 = d2k_test_pq_dgram(dcid, 1, D2K_TEST_PQ_CUT, ch + D2K_TEST_PQ_CUT,
                            chl - D2K_TEST_PQ_CUT, d2, 1500);
    return (*l1 && *l2) ? 0 : -1;
}

#endif
