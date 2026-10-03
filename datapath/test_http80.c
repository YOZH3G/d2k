/* test_http80.c — вставка провайдера в открытый HTTP (задача 51).
 *
 * Пакеты собираются здесь байт в байт так, как их отдаёт очередь: исходящие
 * клиента — с локальным адресом (POSTROUTING, до SNAT), ответы — уже с
 * адресом клиента (FORWARD, после обратной трансляции). Времена — как в
 * захвате на ppp0 03.10.2026: RTT 98 мс, вставка через 0,7 мс после запроса.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_http80.h"
#include "d2k_wire.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s (строка %d)\n", msg, __LINE__); \
            fails++;                                       \
        }                                                  \
    } while (0)

#define MS 1000000ull

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_PSH 0x08
#define F_ACK 0x10

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

typedef struct {
    int v6;
    uint8_t client[16], server[16];
    uint16_t cport, sport;
} flow;

/* Пакет одного направления. to_server — от клиента. */
static size_t pkt(const flow *f, int to_server, uint8_t flags, uint32_t seq, uint32_t ack,
                  const char *payload, uint8_t *o) {
    size_t pl = payload ? strlen(payload) : 0;
    size_t ip = f->v6 ? 40 : 20;
    size_t n = ip + 20 + pl;
    memset(o, 0, n);
    const uint8_t *src = to_server ? f->client : f->server;
    const uint8_t *dst = to_server ? f->server : f->client;
    if (f->v6) {
        o[0] = 0x60; wr16(o + 4, (unsigned)(20 + pl)); o[6] = 6; o[7] = 55;
        memcpy(o + 8, src, 16); memcpy(o + 24, dst, 16);
    } else {
        o[0] = 0x45; wr16(o + 2, (unsigned)n); wr16(o + 4, 0x1234); o[8] = 55; o[9] = 6;
        memcpy(o + 12, src, 4); memcpy(o + 16, dst, 4);
    }
    uint8_t *t = o + ip;
    wr16(t, to_server ? f->cport : f->sport);
    wr16(t + 2, to_server ? f->sport : f->cport);
    wr32(t + 4, seq); wr32(t + 8, ack);
    t[12] = 0x50; t[13] = flags; wr16(t + 14, 64240);
    if (pl) { memcpy(t + 20, payload, pl); }
    return n;
}

static const char GET[] =
    "GET /forum/index.php HTTP/1.1\r\nHost: RuTracker.org:80\r\n"
    "User-Agent: test\r\nAccept: */*\r\n\r\n";
static const char INJECT[] =
    "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\n"
    "Connection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";

#define CISN 1000u
#define SISN 5000000u

static uint8_t b[4096];
static d2k_http80_res r;

/* Рукопожатие и запрос в моменты захвата: SYN 0, SYN/ACK 98 мс, запрос 99 мс. */
static void open_flow(d2k_http80 *h, const flow *f, uint64_t t0, const char *req) {
    size_t n = pkt(f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, t0, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "SYN не проходит как есть");
    n = pkt(f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, t0 + 98 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS, "SYN/ACK не проходит как есть");
    n = pkt(f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, req, b);
    d2k_http80_packet(h, b, n, t0 + 99 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "запрос не проходит как есть");
}

static flow flow4(uint16_t cport) {
    flow f;
    memset(&f, 0, sizeof f);
    const uint8_t c[4] = {192, 168, 1, 117}, s[4] = {195, 82, 146, 214};
    memcpy(f.client, c, 4); memcpy(f.server, s, 4);
    f.cport = cport; f.sport = 80;
    return f;
}

static flow flow6(uint16_t cport) {
    flow f;
    memset(&f, 0, sizeof f);
    f.v6 = 1;
    f.client[0] = 0x20; f.client[1] = 0x01; f.client[2] = 0x0d; f.client[3] = 0xb8; f.client[15] = 0x17;
    f.server[0] = 0x2a; f.server[1] = 0x02; f.server[15] = 0x80;
    f.cport = cport; f.sport = 80;
    return f;
}

static void test_field_injection(int v6) {
    d2k_http80 *h = d2k_http80_new();
    flow f = v6 ? flow6(51000) : flow4(51000);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, 1000 * MS, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT, b);
    d2k_http80_packet(h, b, n, 1000 * MS + 99 * MS + 700000ull, &r);
    CHECK(r.injection, v6 ? "IPv6: вставка 302→lawfilter через 0,7 мс не узнана"
                          : "вставка 302→lawfilter через 0,7 мс не узнана");
    CHECK(r.action == D2K_HTTP80_PASS, "без знания об HTTPS вставка обязана пройти как есть");
    CHECK(strcmp(r.host, "RuTracker.org") == 0, "Host запроса не передан");
    CHECK(strcmp(r.portal, "lawfilter.ertelecom.ru") == 0, "хост блокировки не передан");
    CHECK(r.rtt_ns == 98 * MS && r.reply_ns == 700000ull, "RTT и задержка ответа не те");
    CHECK(r.family == (v6 ? 6 : 4) && r.server_port == 80 && r.client_port == 51000 &&
          memcmp(r.server, f.server, v6 ? 16 : 4) == 0 &&
          memcmp(r.client, f.client, v6 ? 16 : 4) == 0, "адреса потока не те");
    /* Вторая копия — та же вставка, о ней второй раз не сообщаем. */
    d2k_http80_packet(h, b, n, 1000 * MS + 99 * MS + 900000ull, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "вторая копия вставки сообщена повторно");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.injections == 1 && st.requests == 1, "счётчики вставок/запросов не те");
    d2k_http80_free(h);
}

/* То, что вставкой не является, — молча проходит. */
static void test_not_injection(void) {
    static const char own_redirect[] =
        "HTTP/1.1 302 Found\r\nLocation: https://rutracker.org/forum/index.php\r\n"
        "Content-Length: 0\r\n\r\n";
    static const char foreign_redirect[] =
        "HTTP/1.1 302 Found\r\nLocation: https://login.example.net/\r\n"
        "Content-Length: 0\r\n\r\n";
    struct { const char *reply; uint64_t after; uint32_t seq_shift; const char *what; } cases[] = {
        {own_redirect, 700000ull, 0, "обычный 302 сервера на свой хост принят за вставку"},
        {foreign_redirect, 700000ull, 0, "302 на чужой хост без метки блокировки принят за вставку"},
        {INJECT, 120 * MS, 0, "медленный ответ (позже RTT) принят за вставку"},
        {INJECT, 50 * MS, 0, "ответ на 50 мс при RTT 98 мс (позже половины RTT) принят за вставку"},
        {INJECT, 700000ull, 7, "ответ не с начала потока сервера принят за вставку"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        d2k_http80 *h = d2k_http80_new();
        flow f = flow4((uint16_t)(52000 + i));
        open_flow(h, &f, 0, GET);
        size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1 + cases[i].seq_shift,
                       CISN + 1 + (uint32_t)strlen(GET), cases[i].reply, b);
        d2k_http80_packet(h, b, n, 99 * MS + cases[i].after, &r);
        CHECK(!r.injection && r.action == D2K_HTTP80_PASS, cases[i].what);
        d2k_http80_free(h);
    }

    /* Поток, начатый до службы: SYN не видели, RTT не замерен — не решаем. */
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(53000);
    size_t n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, 99 * MS, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "вставка без замеренного RTT признана вставкой");
    d2k_http80_free(h);

    /* Не порт 80 — не наше дело. */
    h = d2k_http80_new();
    f = flow4(54000);
    f.sport = 8080;
    open_flow(h, &f, 0, GET);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "поток не на порт 80 разобран как HTTP");
    d2k_http80_free(h);

    /* POST — не навигация: не трогаем. */
    h = d2k_http80_new();
    f = flow4(55000);
    static const char post[] = "POST / HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 0\r\n\r\n";
    open_flow(h, &f, 0, post);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(post), INJECT, b);
    d2k_http80_packet(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "ответ на POST разобран как вставка в навигацию");
    d2k_http80_free(h);
}

/* Много потоков: таблица ограничена, старые вытесняются, разбор не ломается. */
static void test_table_bound(void) {
    d2k_http80 *h = d2k_http80_new();
    for (unsigned i = 0; i < D2K_HTTP80_FLOWS * 3; i++) {
        flow f = flow4((uint16_t)(10000 + i));
        open_flow(h, &f, (uint64_t)i * MS, GET);
    }
    flow f = flow4((uint16_t)(10000 + D2K_HTTP80_FLOWS * 3 - 1));
    size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, (uint64_t)(D2K_HTTP80_FLOWS * 3 - 1) * MS + 99 * MS + 700000ull, &r);
    CHECK(r.injection, "свежий поток потерян при переполнении таблицы");
    CHECK(d2k_http80_get_stats(h).evicted > 0, "вытеснение не посчитано");
    d2k_http80_free(h);
}

/* Обрезки и мусор не роняют разбор. */
static void test_garbage(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(56000);
    size_t n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    for (size_t cut = 0; cut < n; cut++) {
        d2k_http80_packet(h, b, cut, 0, &r);
        CHECK(r.action == D2K_HTTP80_PASS, "обрезанный пакет не прошёл как есть");
    }
    d2k_http80_free(h);
}

int main(void) {
    test_field_injection(0);
    test_field_injection(1);
    test_not_injection();
    test_table_bound();
    test_garbage();
    (void)rd16; (void)rd32;
    if (fails) {
        printf("test_http80: провалов %d\n", fails);
        return 1;
    }
    printf("test_http80: все проверки прошли\n");
    return 0;
}
