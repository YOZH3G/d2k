/* test_quic_split.c — разрез ClientHello на кадры CRYPTO внутри Initial
 * (задача 40): одна функция ядра, которой пользуются и вопрос замера, и
 * исполнитель датапата.
 *
 * Проверяется настоящим пакетом RFC 9001 A.2 (общий test_quic_vector.h) и
 * собственными Initial, запечатанными модулем провода (кадры, которых в
 * векторе нет: PING, ACK, нехватка добивки).
 *
 * Что обязано выполняться:
 *   - длина датаграммы та же, номер пакета тот же, DCID/SCID/токен те же;
 *   - ClientHello, собранный по смещениям, побайтно тот же, имя то же;
 *   - первым кадром идёт ХВОСТ (смещение > 0), имя не лежит целиком ни в одном
 *     кадре — коробка, читающая кадры по одному, его не находит;
 *   - склеенный хвост датаграммы (следующий пакет) переносится как есть;
 *   - не Initial, мусор, кадр, который разбор не знает, нехватка добивки — -1.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); fails++; } \
                              else { printf("ok   %s\n", msg); } } while (0)

typedef struct { uint64_t off, len; const uint8_t *data; } frame;

/* Расшифровать первый пакет датаграммы и разложить кадры. */
static int open_frames(const uint8_t *p, size_t n, uint8_t *plain, size_t *plain_len,
                       uint64_t *pn, frame *fr, size_t *nfr, size_t *pad, size_t *ping,
                       d2k_qw_hdr *h) {
    if (d2k_qw_hdr_parse(p, n, 0, h) != 0) return -1;
    uint8_t sec[32];
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(h->version, p + h->dcid_off, h->dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(h->version, sec, &k) != 0) return -1;
    if (d2k_qw_open(&k, h, p, 0, plain, plain_len, pn) != 0) return -1;
    *nfr = *pad = *ping = 0;
    for (size_t i = 0; i < *plain_len;) {
        if (plain[i] == 0x00) { (*pad)++; i++; continue; }
        if (plain[i] == 0x01) { (*ping)++; i++; continue; }
        if (plain[i] != 0x06) return -1;
        i++;
        uint64_t off, len; size_t w;
        if (d2k_qw_varint_read(plain + i, *plain_len - i, &off, &w) != 0) return -1;
        i += w;
        if (d2k_qw_varint_read(plain + i, *plain_len - i, &len, &w) != 0) return -1;
        i += w;
        if (len > *plain_len - i) return -1;
        fr[*nfr].off = off; fr[*nfr].len = len; fr[*nfr].data = plain + i;
        (*nfr)++;
        i += (size_t)len;
    }
    return 0;
}

static int name_in_one_frame(const frame *fr, size_t nfr, const char *name) {
    size_t m = strlen(name);
    for (size_t f = 0; f < nfr; f++) {
        for (size_t i = 0; i + m <= fr[f].len; i++) {
            if (memcmp(fr[f].data + i, name, m) == 0) return 1;
        }
    }
    return 0;
}

static void check_v1_vector(void) {
    const uint8_t *in = d2k_test_v1_initial;
    size_t n = sizeof d2k_test_v1_initial;
    uint8_t out[1500];
    size_t out_len = 0;
    CHECK(d2k_quic_initial_split_crypto(in, n, out, sizeof out, &out_len) == 0,
          "RFC 9001 A.2: разрез собрался");
    CHECK(out_len == n, "длина датаграммы та же");

    char a[256], b[256];
    CHECK(d2k_quic_sni(in, n, a, sizeof a) == 0 && d2k_quic_sni(out, out_len, b, sizeof b) == 0 &&
          strcmp(a, b) == 0 && strcmp(b, "example.com") == 0, "имя по смещениям то же");
    uint8_t ch1[1500], ch2[1500];
    size_t l1 = 0, l2 = 0;
    CHECK(d2k_quic_client_hello(in, n, ch1, sizeof ch1, &l1) == 0 &&
          d2k_quic_client_hello(out, out_len, ch2, sizeof ch2, &l2) == 0 &&
          l1 == l2 && memcmp(ch1, ch2, l1) == 0, "ClientHello побайтно тот же");

    uint8_t p1[1500], p2[1500];
    size_t pl1 = 0, pl2 = 0, nf1 = 0, nf2 = 0, pad1 = 0, pad2 = 0, ping1 = 0, ping2 = 0;
    uint64_t pn1 = 99, pn2 = 98;
    frame f1[16], f2[16];
    d2k_qw_hdr h1, h2;
    CHECK(open_frames(in, n, p1, &pl1, &pn1, f1, &nf1, &pad1, &ping1, &h1) == 0 &&
          open_frames(out, out_len, p2, &pl2, &pn2, f2, &nf2, &pad2, &ping2, &h2) == 0,
          "обе датаграммы раскрываются ключами из своего DCID");
    CHECK(pn1 == pn2 && pl1 == pl2, "номер пакета и длина тела те же");
    CHECK(h1.pn_offset == h2.pn_offset && memcmp(in + 1, out + 1, h1.pn_offset - 1) == 0,
          "заголовок до номера пакета тот же (версия, DCID, SCID, токен, длина)");
    CHECK(nf1 == 1 && nf2 == 2, "один кадр CRYPTO стал двумя");
    CHECK(nf2 == 2 && f2[0].off > 0 && f2[1].off == 0 && f2[1].len == f2[0].off &&
          f2[0].off + f2[0].len == f1[0].len, "хвост первым, голова вторым, без дыр и наложений");
    CHECK(name_in_one_frame(f1, nf1, "example.com") && !name_in_one_frame(f2, nf2, "example.com"),
          "имя целиком не лежит ни в одном кадре");
    CHECK(pad2 + 1 + d2k_qw_varint_len(f2[0].off) + d2k_qw_varint_len(f2[0].len) +
          d2k_qw_varint_len(f2[1].len) == pad1 + d2k_qw_varint_len(f1[0].len) ||
          pad2 < pad1, "добивка отдала место заголовку второго кадра");
}

static void check_coalesced_tail(void) {
    uint8_t in[1300];
    memcpy(in, d2k_test_v1_initial, 1200);
    for (size_t i = 1200; i < sizeof in; i++) in[i] = (uint8_t)(i * 7);
    uint8_t out[1500];
    size_t out_len = 0;
    CHECK(d2k_quic_initial_split_crypto(in, sizeof in, out, sizeof out, &out_len) == 0 &&
          out_len == sizeof in && memcmp(out + 1200, in + 1200, 100) == 0,
          "склеенный хвост датаграммы перенесён как есть");
}

static void check_refusals(void) {
    uint8_t out[1500], junk[1200] = {0};
    size_t out_len = 7;
    CHECK(d2k_quic_initial_split_crypto(junk, sizeof junk, out, sizeof out, &out_len) == -1,
          "мусор — отказ");
    CHECK(d2k_quic_initial_split_crypto(d2k_test_v1_initial, 600, out, sizeof out, &out_len) == -1,
          "обрезанная датаграмма — отказ");
    CHECK(d2k_quic_initial_split_crypto(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                        out, 1199, &out_len) == -1, "мал буфер — отказ");
    uint8_t bad[1200];
    memcpy(bad, d2k_test_v1_initial, sizeof bad);
    bad[600] ^= 1;
    CHECK(d2k_quic_initial_split_crypto(bad, sizeof bad, out, sizeof out, &out_len) == -1,
          "тег AEAD не сошёлся — отказ, пакет не трогается");
    CHECK(d2k_quic_initial_split_crypto(NULL, 0, out, sizeof out, &out_len) == -1, "NULL — отказ");
}

/* Свой Initial: CRYPTO, затем кадр, который разбор не знает (ACK). */
static void check_unknown_frame(void) {
    uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8}, sec[32];
    d2k_qw_keys k;
    CHECK(d2k_qw_initial_secret(D2K_QW_V1, dcid, 8, D2K_QW_CLIENT, sec) == 0 &&
          d2k_qw_keys_from_secret(D2K_QW_V1, sec, &k) == 0, "ключи");
    uint8_t body[1100];
    memset(body, 0, sizeof body);
    size_t b = 0;
    body[b++] = 0x06; body[b++] = 0x00; body[b++] = 0x40; body[b++] = 40;
    for (int i = 0; i < 40; i++) body[b++] = (uint8_t)i;
    body[b++] = 0x02; body[b++] = 0; body[b++] = 0; body[b++] = 0; body[b++] = 0; /* ACK */
    uint8_t hdr[64], pkt[1500], out[1500];
    size_t hl = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL, dcid, 8, NULL, 0,
                                2, sizeof body);
    size_t pl = d2k_qw_seal(&k, 1, hdr, hl, 0, 2, body, sizeof body, pkt, sizeof pkt);
    size_t out_len = 0;
    CHECK(pl > 0 && d2k_quic_initial_split_crypto(pkt, pl, out, sizeof out, &out_len) == -1,
          "кадр, который разбор не знает, — отказ (не выбрасываем чужое)");
    /* Без добивки места под второй кадр нет. */
    uint8_t tight[60];
    size_t t = 0;
    tight[t++] = 0x06; tight[t++] = 0x00; tight[t++] = 56;
    for (int i = 0; i < 56; i++) tight[t++] = (uint8_t)(i + 1);
    hl = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL, dcid, 8, NULL, 0, 2, t);
    pl = d2k_qw_seal(&k, 1, hdr, hl, 0, 2, tight, t, pkt, sizeof pkt);
    CHECK(pl > 0 && d2k_quic_initial_split_crypto(pkt, pl, out, sizeof out, &out_len) == -1,
          "нет добивки под заголовок второго кадра — отказ, а не датаграмма длиннее");
    /* С добивкой, без имени: режется пополам самый длинный кадр. */
    uint8_t roomy[200];
    memset(roomy, 0, sizeof roomy);
    memcpy(roomy, tight, t);
    roomy[t] = 0x01; /* PING сохраняется */
    hl = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL, dcid, 8, NULL, 0, 2,
                         sizeof roomy);
    pl = d2k_qw_seal(&k, 1, hdr, hl, 5, 2, roomy, sizeof roomy, pkt, sizeof pkt);
    uint8_t p2[1500];
    size_t pl2 = 0, nf = 0, pad = 0, ping = 0;
    uint64_t pn = 0;
    frame fr[8];
    d2k_qw_hdr h;
    CHECK(pl > 0 && d2k_quic_initial_split_crypto(pkt, pl, out, sizeof out, &out_len) == 0 &&
          out_len == pl && open_frames(out, out_len, p2, &pl2, &pn, fr, &nf, &pad, &ping, &h) == 0 &&
          pn == 5 && nf == 2 && ping == 1 && fr[0].off == 28 && fr[0].len == 28 &&
          fr[1].off == 0 && fr[1].len == 28 && fr[0].data[0] == 29,
          "без имени: самый длинный кадр пополам, хвост первым, PING и номер пакета на месте");
}

int main(void) {
    check_v1_vector();
    check_coalesced_tail();
    check_refusals();
    check_unknown_frame();
    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    puts("QUIC split CRYPTO: passed");
    return 0;
}
