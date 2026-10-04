/* test_icmpguard.c — ICMP «время жизни истекло» на СОБСТВЕННУЮ фальшивку.
 *
 * Поле 04.10.2026, KN-1811: Safari открывает rua.gr по QUIC, план шлёт две
 * фальшивки Initial с TTL 3, третий узел (62.115.145.221) отвечает ICMP
 * time-exceeded, NAT роутера отдаёт его клиенту, и Network.framework
 * закрывает свой UDP-сокет — рукопожатие умирает. Здесь — ровно тот ICMP,
 * побайтно из icmp-rua.pcap (br0, после обратного NAT), и окружение: что
 * должно пройти нетронутым (traceroute, PMTU, чужие потоки, реальные пакеты
 * клиента, просроченная запись). */
#include <stdio.h>
#include <string.h>
#include "d2k_icmpguard.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define S (UINT64_C(1000000000))

/* icmp-rua.pcap, 11:00:20.740772, IP-уровень (без Ethernet). */
static const uint8_t field_icmp[] = {
    0x45,0x70,0x00,0x38,0x00,0x00,0x00,0x00,0xfb,0x01,0x2d,0x19,0x3e,0x73,0x91,0xdd,
    0xc0,0xa8,0x01,0x43,0x0b,0x00,0xe1,0x72,0x00,0x00,0x00,0x00,0x45,0x70,0x04,0xcc,
    0x00,0x01,0x40,0x00,0x01,0x11,0x16,0x59,0xc0,0xa8,0x01,0x43,0x68,0x15,0x34,0x57,
    0xd8,0x8b,0x01,0xbb,0x04,0xb8,0x34,0x8e,
};

/* Фальшивка Initial, как её собрал wire_udp.c: 1228 байт, ID = ID клиента + 1
 * (клиент шлёт 0), DF, TTL 3, 192.168.1.67:55435 -> 104.21.52.87:443. Очередь
 * висит на POSTROUTING до SNAT, поэтому адрес — локальный клиента. */
static size_t fake4(uint8_t *p, uint8_t ttl, uint16_t id, uint16_t sport) {
    size_t n = 1228;
    memset(p, 0, n);
    p[0] = 0x45; p[2] = n >> 8; p[3] = n & 0xff;
    p[4] = id >> 8; p[5] = id & 0xff; p[6] = 0x40; p[8] = ttl; p[9] = 17;
    p[12] = 192; p[13] = 168; p[14] = 1; p[15] = 67;
    p[16] = 104; p[17] = 21; p[18] = 52; p[19] = 87;
    p[20] = sport >> 8; p[21] = sport & 0xff; p[22] = 0x01; p[23] = 0xbb;
    p[24] = (n - 20) >> 8; p[25] = (n - 20) & 0xff;
    p[28] = 0xc0;   /* QUIC long header */
    return n;
}

/* ICMP type/code с цитатой первых len_quote байт пакета q (как это делает узел:
 * заголовок IP + 8 байт L4 — минимум RFC 792). */
static size_t icmp4(uint8_t *out, uint8_t type, uint8_t code, const uint8_t *q, size_t quote) {
    size_t n = 20 + 8 + quote;
    memset(out, 0, n);
    out[0] = 0x45; out[2] = n >> 8; out[3] = n & 0xff; out[8] = 251; out[9] = 1;
    out[12] = 62; out[13] = 115; out[14] = 145; out[15] = 221;
    out[16] = 192; out[17] = 168; out[18] = 1; out[19] = 67;
    out[20] = type; out[21] = code;
    memcpy(out + 28, q, quote);
    return n;
}

static size_t fake6(uint8_t *p, uint8_t hop, uint8_t proto, uint16_t sport, uint16_t dport, size_t body) {
    size_t l4 = proto == 6 ? 20 : 8;
    size_t n = 40 + l4 + body;
    memset(p, 0, n);
    p[0] = 0x60; p[4] = (uint8_t)((n - 40) >> 8); p[5] = (uint8_t)((n - 40) & 0xff);
    p[6] = proto; p[7] = hop;
    p[8] = 0x20; p[9] = 0x01; p[10] = 0x0d; p[11] = 0xb8; p[23] = 0x67;  /* 2001:db8::67 */
    p[24] = 0x26; p[25] = 0x06; p[26] = 0x47; p[27] = 0x00; p[39] = 0x87; /* 2606:4700::87 */
    p[40] = sport >> 8; p[41] = sport & 0xff; p[42] = dport >> 8; p[43] = dport & 0xff;
    if (proto == 17) {
        p[44] = (uint8_t)((n - 40) >> 8); p[45] = (uint8_t)((n - 40) & 0xff);
        p[46] = 0x5a; p[47] = 0xa5;
    } else {
        p[44] = 0x11; p[45] = 0x22; p[46] = 0x33; p[47] = 0x44; p[52] = 0x50; p[53] = 0x18;
    }
    return n;
}

static size_t icmp6(uint8_t *out, uint8_t type, uint8_t code, const uint8_t *q, size_t quote) {
    size_t n = 40 + 8 + quote;
    memset(out, 0, n);
    out[0] = 0x60; out[4] = (uint8_t)((n - 40) >> 8); out[5] = (uint8_t)((n - 40) & 0xff);
    out[6] = 58; out[7] = 250;
    out[8] = 0x20; out[9] = 0x01; out[10] = 0x0d; out[11] = 0xb8; out[23] = 0x03;
    out[24] = 0x20; out[25] = 0x01; out[26] = 0x0d; out[27] = 0xb8; out[39] = 0x67;
    out[40] = type; out[41] = code;
    memcpy(out + 48, q, quote);
    return n;
}

int main(void) {
    static d2k_icmpguard g;
    uint8_t fk[1500], ic[1500], q[1500];
    size_t n, m;
    const uint64_t t0 = 100 * S;

    /* --- поле: тот самый ICMP ------------------------------------------- */
    d2k_icmpguard_init(&g);
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp, t0) == 0);  /* записи нет */
    n = fake4(fk, 3, 1, 55435);
    CHECK(d2k_icmpguard_note(&g, fk, n, 63, t0) == 1);
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp, t0 + S / 30) == 1);
    CHECK(d2k_icmpguard_dropped(&g) == 1);
    /* Вторая фальшивка того же потока — та же цитата, тоже своя. */
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp, t0 + S / 30) == 1);
    /* Просрочено: старая запись не оправдывает чужой ICMP. */
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp, t0 + D2K_ICMPGUARD_KEEP_NS + 1) == 0);
    /* Отрезанная цитата (меньше 8 байт L4) — не судим, пропускаем. */
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp - 1, t0 + S / 30) == 0);

    /* Пакет без пониженного TTL — не фальшивка и не записывается. */
    d2k_icmpguard_init(&g);
    n = fake4(fk, 63, 1, 55435);
    CHECK(d2k_icmpguard_note(&g, fk, n, 63, t0) == 0);
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp, t0) == 0);

    /* --- окружение при записанной фальшивке ------------------------------ */
    d2k_icmpguard_init(&g);
    n = fake4(fk, 3, 1, 55435);
    CHECK(d2k_icmpguard_note(&g, fk, n, 63, t0) == 1);
    /* Настоящий Initial клиента того же потока (ID 0): его ICMP не наш. */
    memcpy(q, fk, 28); q[4] = 0; q[5] = 0; q[8] = 1;
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* traceroute из LAN: UDP 33434, свой кортеж. */
    memcpy(q, fk, 28); q[8] = 1; q[20] = 0xd4; q[21] = 0x31; q[22] = 0x82; q[23] = 0x9a;
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* PMTU «нужна фрагментация» с цитатой той же фальшивки — не трогаем. */
    memcpy(q, fk, 28);
    m = icmp4(ic, 3, 4, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* Time-exceeded при сборке фрагментов (код 1) — не TTL, не наш. */
    memcpy(q, fk, 28); q[8] = 1;
    m = icmp4(ic, 11, 1, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* Другой порт клиента. */
    memcpy(q, fk, 28); q[8] = 1; q[21] ^= 1;
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* Цитата с TTL выше посланного — не та посылка. */
    memcpy(q, fk, 28); q[8] = 4;
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* Сама фальшивка (не ICMP) — не судится. */
    CHECK(d2k_icmpguard_check(&g, fk, n, t0) == 0);
    CHECK(d2k_icmpguard_dropped(&g) == 0);

    /* Узел цитирует больше 8 байт (RFC 1812) — тоже наш. */
    memcpy(q, fk, 128); q[8] = 1;
    m = icmp4(ic, 11, 0, q, 128);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 1);

    /* ID 0 в посылке: ядро ставит свой (raw(7)), сверять ID нечем — сверяем
       длину и слово L4. */
    d2k_icmpguard_init(&g);
    n = fake4(fk, 3, 0, 55435);
    CHECK(d2k_icmpguard_note(&g, fk, n, 63, t0) == 1);
    memcpy(q, fk, 28); q[8] = 1; q[4] = 0x12; q[5] = 0x34;
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 1);

    /* --- TCP-фальшивка: сверяется номер последовательности --------------- */
    d2k_icmpguard_init(&g);
    n = fake4(fk, 4, 0x2001, 40000);
    fk[9] = 6; n = 20 + 20 + 100; fk[2] = 0; fk[3] = (uint8_t)n;
    fk[24] = 0xde; fk[25] = 0xad; fk[26] = 0xbe; fk[27] = 0xef; fk[32] = 0x50;
    CHECK(d2k_icmpguard_note(&g, fk, n, 63, t0) == 1);
    memcpy(q, fk, 28); q[8] = 1;
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 1);
    q[27] ^= 1;   /* другой сегмент того же потока */
    m = icmp4(ic, 11, 0, q, 28);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);

    /* --- IPv6 ------------------------------------------------------------ */
    d2k_icmpguard_init(&g);
    n = fake6(fk, 3, 17, 55435, 443, 1172);
    memcpy(q, fk, 48); q[7] = 1;
    m = icmp6(ic, 3, 0, q, 48);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);                /* записи нет */
    CHECK(d2k_icmpguard_note(&g, fk, n, 64, t0) == 1);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 1);
    /* Узел IPv6 цитирует до 1232 байт — длинная цитата. */
    memcpy(q, fk, 600); q[7] = 1;
    m = icmp6(ic, 3, 0, q, 600);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 1);
    /* Packet Too Big (тип 2) с той же цитатой — PMTU, пропускаем. */
    memcpy(q, fk, 48);
    m = icmp6(ic, 2, 0, q, 48);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* traceroute6 из LAN: свой порт назначения. */
    memcpy(q, fk, 48); q[7] = 1; q[42] = 0x82; q[43] = 0x9a;
    m = icmp6(ic, 3, 0, q, 48);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* Настоящий пакет клиента того же потока другой длины. */
    memcpy(q, fk, 48); q[7] = 1; q[5] ^= 0x10;
    m = icmp6(ic, 3, 0, q, 48);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 0);
    /* Просрочено. */
    memcpy(q, fk, 48); q[7] = 1;
    m = icmp6(ic, 3, 0, q, 48);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0 + D2K_ICMPGUARD_KEEP_NS + 1) == 0);
    /* TCP по IPv6. */
    n = fake6(fk, 2, 6, 40001, 443, 50);
    CHECK(d2k_icmpguard_note(&g, fk, n, 64, t0) == 1);
    memcpy(q, fk, 48); q[7] = 0;
    m = icmp6(ic, 3, 0, q, 48);
    CHECK(d2k_icmpguard_check(&g, ic, m, t0) == 1);

    /* --- кольцо: старые записи вытесняются, а не копятся ---------------- */
    d2k_icmpguard_init(&g);
    n = fake4(fk, 3, 1, 55435);
    CHECK(d2k_icmpguard_note(&g, fk, n, 63, t0) == 1);
    for (unsigned i = 0; i < D2K_ICMPGUARD_SLOTS; i++) {
        uint8_t other[1500];
        size_t on = fake4(other, 3, 1, (uint16_t)(1000 + i));
        (void)d2k_icmpguard_note(&g, other, on, 63, t0);
    }
    CHECK(d2k_icmpguard_check(&g, field_icmp, sizeof field_icmp, t0) == 0);

    /* Мусор не роняет разбор. */
    CHECK(d2k_icmpguard_check(&g, NULL, 0, t0) == 0);
    CHECK(d2k_icmpguard_check(&g, field_icmp, 20, t0) == 0);
    CHECK(d2k_icmpguard_note(&g, NULL, 0, 63, t0) == 0);
    CHECK(d2k_icmpguard_note(&g, fk, 10, 63, t0) == 0);

    if (fails) { fprintf(stderr, "test_icmpguard: %d провал(ов)\n", fails); return 1; }
    printf("test_icmpguard: все проверки прошли\n");
    return 0;
}
