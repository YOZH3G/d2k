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
#include "d2k_httpup.h"

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
#define PKT(h, p, n, t, res) d2k_http80_packet((h), (p), (n), (t), 0, out, sizeof out, rst, sizeof rst, (res))
static d2k_http80_res r;
static uint8_t out[2048], rst[128];

/* Рукопожатие и запрос в моменты захвата: SYN 0, SYN/ACK 98 мс, запрос 99 мс. */
static void open_flow(d2k_http80 *h, const flow *f, uint64_t t0, const char *req) {
    size_t n = pkt(f, 1, F_SYN, CISN, 0, NULL, b);
    PKT(h, b, n, t0, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "SYN не проходит как есть");
    n = pkt(f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    PKT(h, b, n, t0 + 98 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS, "SYN/ACK не проходит как есть");
    n = pkt(f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, req, b);
    PKT(h, b, n, t0 + 99 * MS, &r);
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
    PKT(h, b, n, 1000 * MS + 99 * MS + 700000ull, &r);
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
    PKT(h, b, n, 1000 * MS + 99 * MS + 900000ull, &r);
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
        PKT(h, b, n, 99 * MS + cases[i].after, &r);
        CHECK(!r.injection && r.action == D2K_HTTP80_PASS, cases[i].what);
        d2k_http80_free(h);
    }

    /* Поток, начатый до службы: SYN не видели, RTT не замерен — не решаем. */
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(53000);
    size_t n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, 99 * MS, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "вставка без замеренного RTT признана вставкой");
    d2k_http80_free(h);

    /* Не порт 80 — не наше дело. */
    h = d2k_http80_new();
    f = flow4(54000);
    f.sport = 8080;
    open_flow(h, &f, 0, GET);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(!r.injection, "поток не на порт 80 разобран как HTTP");
    d2k_http80_free(h);

    /* POST — не навигация: не трогаем. */
    h = d2k_http80_new();
    f = flow4(55000);
    static const char post[] = "POST / HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 0\r\n\r\n";
    open_flow(h, &f, 0, post);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(post), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
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
    PKT(h, b, n, (uint64_t)(D2K_HTTP80_FLOWS * 3 - 1) * MS + 99 * MS + 700000ull, &r);
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
        PKT(h, b, cut, 0, &r);
        CHECK(r.action == D2K_HTTP80_PASS, "обрезанный пакет не прошёл как есть");
    }
    d2k_http80_free(h);
}

/* Вердикт и RST — подделки: замер того, что датапат сделал бы с очередью. */
typedef struct { int fail_verdict, payload_calls, accept_calls, rst_calls; size_t payload_len; } fake_io;
static int io_payload(void *c, const uint8_t *p, size_t n) {
    fake_io *f = c; (void)p; f->payload_calls++; f->payload_len = n;
    return f->fail_verdict ? -1 : 0;
}
static int io_accept(void *c) { ((fake_io *)c)->accept_calls++; return 0; }
static int io_rst(void *c, const uint8_t *p, size_t n) {
    (void)p; (void)n; ((fake_io *)c)->rst_calls++; return 0;
}
static int swap(d2k_http80 *h, d2k_http80_res *res, fake_io *f) {
    d2k_http80_io io = {io_payload, io_accept, io_rst, f};
    return d2k_http80_swap(h, res, out, rst, &io);
}

static int ip4_header_ok(const uint8_t *p) {
    uint32_t acc = 0;
    for (size_t i = 0; i < 20; i += 2) { acc += rd16(p + i); }
    while (acc >> 16) { acc = (acc & 0xffffu) + (acc >> 16); }
    return acc == 0xffffu;
}

/* HTTPS подтверждён: клиент получает 307 в том же потоке, сервер — RST,
   остальное от сервера снимается. */
static void test_answer(int v6) {
    d2k_http80 *h = d2k_http80_new();
    const uint64_t T = 5000 * MS;
    CHECK(d2k_http80_set_https(h, "rutracker.org.", 14, T + 3600 * 1000 * MS) == 0,
          "имя с HTTPS не принято");
    flow f = v6 ? flow6(51500) : flow4(51500);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, T, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT, b);
    PKT(h, b, n, T + 99 * MS + 700000ull, &r);
    CHECK(r.injection && r.action == D2K_HTTP80_REPLACE,
          v6 ? "IPv6: вставка при подтверждённом HTTPS не заменена" :
               "вставка при подтверждённом HTTPS не заменена");
    {
        d2k_http80_res keep = r;
        fake_io io = {0, 0, 0, 0, 0};
        CHECK(swap(h, &keep, &io) == 1 && keep.answered && io.payload_calls == 1 &&
              io.payload_len == keep.len && io.rst_calls == 1 && io.accept_calls == 0,
              "удачная замена: не тот порядок вердикта и RST");
    }

    char want[1024];
    size_t wl = d2k_httpup_redirect_https("RuTracker.org", "/forum/index.php", want, sizeof want);
    CHECK(wl > 0 && strstr(want, "HTTP/1.1 307 Temporary Redirect\r\n") == want &&
          strstr(want, "Location: https://RuTracker.org/forum/index.php\r\n") &&
          strstr(want, "Content-Length: 0\r\n") && strstr(want, "Connection: close\r\n"),
          "307 собран не тем");
    size_t ip = v6 ? 40 : 20;
    CHECK(r.len == ip + 20 + wl, "длина пакета-замены не та");
    const uint8_t *o = out, *t = out + ip;
    if (v6) {
        CHECK(o[0] >> 4 == 6 && rd16(o + 4) == 20 + wl && o[6] == 6, "IPv6-заголовок замены не тот");
        CHECK(memcmp(o + 8, f.server, 16) == 0 && memcmp(o + 24, f.client, 16) == 0,
              "IPv6: адреса замены не те");
    } else {
        CHECK(o[0] == 0x45 && rd16(o + 2) == 20 + 20 + wl && o[9] == 6, "IPv4-заголовок замены не тот");
        CHECK(memcmp(o + 12, f.server, 4) == 0 && memcmp(o + 16, f.client, 4) == 0,
              "IPv4: адреса замены не те");
        CHECK(ip4_header_ok(o), "сумма IPv4-заголовка замены неверна");
    }
    CHECK(rd16(t) == 80 && rd16(t + 2) == 51500, "порты замены не те");
    CHECK(rd32(t + 4) == SISN + 1, "seq замены не начало потока сервера");
    CHECK(rd32(t + 8) == req_end, "ack замены не конец запроса");
    CHECK(t[13] == (F_FIN | F_PSH | F_ACK), "флаги замены не FIN|PSH|ACK");
    CHECK(memcmp(t + 20, want, wl) == 0, "нагрузка замены не 307");
    CHECK(d2k_wire_tcp_checksum_ok(out, r.len), "TCP-сумма замены неверна");

    /* RST к серверу: от клиента, с конца запроса. */
    CHECK(r.rst_len == ip + 20, "RST к серверу не собран");
    const uint8_t *q = rst + ip;
    if (v6) {
        CHECK(memcmp(rst + 8, f.client, 16) == 0 && memcmp(rst + 24, f.server, 16) == 0,
              "IPv6: адреса RST не те");
    } else {
        CHECK(memcmp(rst + 12, f.client, 4) == 0 && memcmp(rst + 16, f.server, 4) == 0,
              "IPv4: адреса RST не те");
        CHECK(ip4_header_ok(rst), "сумма IPv4-заголовка RST неверна");
    }
    CHECK(rd16(q) == 51500 && rd16(q + 2) == 80, "порты RST не те");
    CHECK(rd32(q + 4) == req_end && (q[13] & F_RST), "RST не с конца запроса");
    CHECK(d2k_wire_tcp_checksum_ok(rst, r.rst_len), "TCP-сумма RST неверна");

    /* Вторая копия, отдельный FIN вставки, поздний настоящий ответ — снимаются. */
    PKT(h, b, n, T + 99 * MS + 900000ull, &r);
    CHECK(r.action == D2K_HTTP80_DROP && !r.injection, "вторая копия вставки не снята");
    n = pkt(&f, 0, F_ACK | F_FIN, SISN + 1 + (uint32_t)strlen(INJECT), req_end, NULL, b);
    PKT(h, b, n, T + 99 * MS + 950000ull, &r);
    CHECK(r.action == D2K_HTTP80_DROP, "FIN вставки не снят");
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, req_end, "HTTP/1.1 200 OK\r\n\r\n", b);
    PKT(h, b, n, T + 200 * MS, &r);
    CHECK(r.action == D2K_HTTP80_DROP, "поздний пакет сервера не снят");
    /* Клиент закрывает своё — это не наше дело. */
    n = pkt(&f, 1, F_ACK | F_FIN, req_end, SISN + 2 + (uint32_t)wl, NULL, b);
    PKT(h, b, n, T + 200 * MS, &r);
    CHECK(r.action == D2K_HTTP80_PASS, "пакет клиента после замены снят");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.answered == 1 && st.dropped == 3, "счётчики замены не те");
    d2k_http80_free(h);
}

/* Ядро не приняло вердикт с заменой (ревью I3): вставка уходит как есть,
   поток не «отвечен», серверу RST не идёт, вторая копия не снимается. */
static void test_swap_failure(void) {
    d2k_http80 *h = d2k_http80_new();
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, 1000 * MS) == 0, "имя не принято");
    flow f = flow4(58000);
    open_flow(h, &f, 0, GET);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, SISN + 1, req_end, INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(r.action == D2K_HTTP80_REPLACE, "замена не предложена");
    fake_io io = {1, 0, 0, 0, 0};
    CHECK(swap(h, &r, &io) == 0 && !r.answered, "неудачная замена сочтена удачной");
    CHECK(io.payload_calls == 1 && io.accept_calls == 1 && io.rst_calls == 0,
          "после неудачной замены не выпущен оригинал или ушёл RST");
    PKT(h, b, n, 99 * MS + 900000ull, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "вторая копия снята после неудачной замены");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.answered == 0 && st.swap_failed == 1 && st.dropped == 0, "счётчики неудачи не те");
    d2k_http80_free(h);
}

/* Задержка самого d2kd (ревью M1): SYN/ACK пролежал в очереди 200 мс. По
   своим часам d2kd RTT 300 мс, и настоящий ответ через 60 мс выглядит
   вставкой. Метки ядра (приём пакета) дают настоящие 98 мс — не вставка. */
static void test_kernel_clock(void) {
    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(59000);
    const uint64_t K = 1700000000ull * 1000000000ull;
    size_t n = pkt(&f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, 0, K, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, 300 * MS, K + 98 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, 301 * MS, K + 99 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 361 * MS, K + 159 * MS, out, sizeof out, rst, sizeof rst, &r);
    CHECK(!r.injection, "задержка d2kd превратила настоящий ответ во вставку");
    d2k_http80_free(h);

    /* Тот же поток, ответ через 0,7 мс по меткам ядра — вставка. */
    h = d2k_http80_new();
    n = pkt(&f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, 0, K, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, 300 * MS, K + 98 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, 301 * MS, K + 99 * MS, out, sizeof out, rst, sizeof rst, &r);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 302 * MS, K + 99 * MS + 700000ull, out, sizeof out, rst, sizeof rst, &r);
    CHECK(r.injection && r.rtt_ns == 98 * MS && r.reply_ns == 700000ull,
          "вставка по меткам ядра не узнана или замер не по ядру");
    d2k_http80_free(h);
}

static void test_https_table(void) {
    d2k_http80 *h = d2k_http80_new();
    CHECK(d2k_http80_set_https(h, "", 0, 10) != 0, "пустое имя принято");
    CHECK(d2k_http80_set_https(h, "bad name", 8, 10) != 0, "имя с пробелом принято");
    CHECK(d2k_http80_set_https(h, "Example.COM", 11, 100) == 0, "имя не принято");
    CHECK(d2k_http80_https(h, "example.com", 99), "имя не найдено без учёта регистра");
    CHECK(!d2k_http80_https(h, "example.com", 100), "имя живёт дольше срока");
    CHECK(!d2k_http80_https(h, "www.example.com", 1), "поддомен принят за имя");
    CHECK(d2k_http80_set_https(h, "example.com", 11, 0) == 0 && !d2k_http80_https(h, "example.com", 1),
          "имя не снимается нулевым сроком");
    char name[32];
    for (unsigned i = 0; i < D2K_HTTP80_NAMES + 20; i++) {
        int k = snprintf(name, sizeof name, "n%u.example", i);
        CHECK(d2k_http80_set_https(h, name, (size_t)k, 1000 + i) == 0, "полная таблица отказала");
    }
    int k = snprintf(name, sizeof name, "n%u.example", D2K_HTTP80_NAMES + 19);
    (void)k;
    CHECK(d2k_http80_https(h, name, 1), "свежее имя вытеснено");
    CHECK(!d2k_http80_https(h, "n0.example", 1), "вытеснено не самое раннее");

    /* Срок вышел — вставка снова проходит как есть. */
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, 10 * MS) == 0, "имя не принято");
    flow f = flow4(57000);
    open_flow(h, &f, 0, GET);
    size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    PKT(h, b, n, 99 * MS + 700000ull, &r);
    CHECK(r.injection && !r.answered && r.action == D2K_HTTP80_PASS,
          "истёкшее знание об HTTPS всё ещё переводит на https");
    d2k_http80_free(h);

    /* Замена не помещается в буфер — вставка проходит, а не теряется. */
    h = d2k_http80_new();
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, 1000 * MS) == 0, "имя не принято");
    f = flow4(57001);
    open_flow(h, &f, 0, GET);
    n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, 99 * MS + 700000ull, 0, out, 64, rst, sizeof rst, &r);
    CHECK(r.injection && r.action == D2K_HTTP80_PASS, "замена без места не прошла как есть");
    d2k_http80_free(h);
}

/* KEEP-ALIVE (поле 04.10.2026): первый запрос получил настоящий ответ, второй
   запрос того же соединения — вставку. Узнавание и замена 307 — только для
   первого ответа потока: на следующем запросе ни события, ни замены, ни
   снятия пакетов, даже если имя с HTTPS. План имени покрывает такие запросы
   сам (session.c); здесь — только «не сработать мимо». */
static void test_keepalive_later(void) {
    d2k_http80 *h = d2k_http80_new();
    const uint64_t T = 7000 * MS;
    CHECK(d2k_http80_set_https(h, "rutracker.org", 13, T + 3600 * 1000 * MS) == 0,
          "имя с HTTPS не принято");
    flow f = flow4(52000);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &f, T, GET);
    static const char OK200[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    size_t n = pkt(&f, 0, F_ACK | F_PSH, SISN + 1, req_end, OK200, b);
    PKT(h, b, n, T + 99 * MS + 98 * MS, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "настоящий ответ принят за вставку");
    uint32_t s2 = SISN + 1 + (uint32_t)strlen(OK200);
    n = pkt(&f, 1, F_ACK | F_PSH, req_end, s2, GET, b);
    PKT(h, b, n, T + 300 * MS, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS, "второй запрос соединения не прошёл как есть");
    uint32_t req2_end = req_end + (uint32_t)strlen(GET);
    n = pkt(&f, 0, F_ACK | F_PSH | F_FIN, s2, req2_end, INJECT, b);
    PKT(h, b, n, T + 300 * MS + 500000ull, &r);
    CHECK(!r.injection && r.action == D2K_HTTP80_PASS && r.len == 0,
          "вставка на втором запросе соединения сработала узнаванием/заменой");
    PKT(h, b, n, T + 300 * MS + 600000ull, &r);
    CHECK(r.action == D2K_HTTP80_PASS, "копия вставки на втором запросе снята");
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.requests == 1 && st.injections == 0 && st.answered == 0 && st.dropped == 0,
          "счётчики после второго запроса не те");
    d2k_http80_free(h);
}

/* ПОЛЕ 04.10.2026, 13:17:59: Safari показал портал провайдера, а у d2kd
   за всю минуту «запросов 13 → 13» и ни одной вставки — событие
   контроллеру не родилось вовсе. По одному счётчику запросов не отличить
   «запроса к :80 не было» (кэш браузера) от «был, но его здесь не разобрать»:
   соединение открыто до запуска d2kd (keep-alive), запрос не целиком в
   первом сегменте (большие Cookie), следующий запрос соединения. Каждый
   такой случай — свой счётчик в сводке. */
static void test_unseen_counted(void) {
    d2k_http80 *h = d2k_http80_new();
    const uint64_t T = 9000 * MS;
    /* 1. Соединение без SYN в таблице: запрос по keep-alive, открытому до
       запуска d2kd. */
    flow a = flow4(53000);
    size_t n = pkt(&a, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    PKT(h, b, n, T, &r);
    CHECK(r.action == D2K_HTTP80_PASS && !r.injection, "запрос чужого соединения не прошёл как есть");
    /* Чистый ACK клиента без нагрузки — не запрос, не считается. */
    n = pkt(&a, 1, F_ACK, CISN + 1, SISN + 1, NULL, b);
    PKT(h, b, n, T + MS, &r);
    /* 2. Запрос не целиком в первом сегменте. */
    flow c = flow4(53001);
    open_flow(h, &c, T, "GET / HTTP/1.1\r\nHost: www.fast-torrent.ru\r\nCookie: a=b\r\n");
    /* 3. Второй запрос того же соединения после настоящего ответа. */
    flow k = flow4(53002);
    uint32_t req_end = CISN + 1 + (uint32_t)strlen(GET);
    open_flow(h, &k, T, GET);
    static const char OK200[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    n = pkt(&k, 0, F_ACK | F_PSH, SISN + 1, req_end, OK200, b);
    PKT(h, b, n, T + 200 * MS, &r);
    n = pkt(&k, 1, F_ACK | F_PSH, req_end, SISN + 1 + (uint32_t)strlen(OK200), GET, b);
    PKT(h, b, n, T + 300 * MS, &r);
    d2k_http80_stats st = d2k_http80_get_stats(h);
    CHECK(st.requests == 1, "разобранных запросов не 1");
    CHECK(st.untracked == 1, "запрос соединения без SYN в таблице не сосчитан");
    CHECK(st.unparsed == 1, "запрос не целиком в первом сегменте не сосчитан");
    CHECK(st.later == 1, "следующий запрос соединения не сосчитан");
    d2k_http80_free(h);
}

int main(void) {
    test_field_injection(0);
    test_field_injection(1);
    test_not_injection();
    test_table_bound();
    test_garbage();
    test_answer(0);
    test_answer(1);
    test_https_table();
    test_swap_failure();
    test_kernel_clock();
    test_keepalive_later();
    test_unseen_counted();
    if (fails) {
        printf("test_http80: провалов %d\n", fails);
        return 1;
    }
    printf("test_http80: все проверки прошли\n");
    return 0;
}
