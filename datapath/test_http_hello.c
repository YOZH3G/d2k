/* test_http_hello.c — открытый HTTP как «приветствие» (задача 51, шаг 4).
 *
 * Запрос GET/HEAD с Host — вход плана обхода HTTP: имя = Host, форма
 * D2K_PLAN_SHAPE_HTTP, план объявляет протокол http (minexec 11). Главное
 * здесь — разделение: HTTP-план не достаётся TLS, TLS-план не достаётся
 * HTTP, и запись имени HTTP не заслоняет TLS-приветствию адресный план.
 * Всё непонятое проходит как есть.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_http80.h"
#include "d2k_plan.h"
#include "d2k_plans.h"
#include "d2k_session.h"
#include "d2k_journal.h"
#include "d2k_wire.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s (строка %d)\n", msg, __LINE__); \
            fails++;                                       \
        }                                                  \
    } while (0)

static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* --- сборка плана TLV ------------------------------------------------------ */
typedef struct { uint8_t b[512]; size_t n; unsigned recs; } tlv;
static void tlv_begin(tlv *t, unsigned minexec) {
    memset(t, 0, sizeof *t);
    memcpy(t->b, "D2KP", 4); wr16(t->b + 4, 1); wr16(t->b + 6, minexec);
    t->n = 12;
}
static void tlv_rec(tlv *t, unsigned type, const uint8_t *v, size_t len) {
    wr16(t->b + t->n, type); wr16(t->b + t->n + 2, (unsigned)len);
    memcpy(t->b + t->n + 4, v, len);
    t->n += 4 + len; t->recs++;
    wr16(t->b + 10, t->recs);
}
static void rec_proto(tlv *t, uint8_t tr, uint8_t proto) {
    uint8_t v[2] = {tr, proto}; tlv_rec(t, 0x0002, v, 2);
}
static void rec_split(tlv *t, unsigned anchor, int off) {
    uint8_t v[4]; wr16(v, anchor); wr16(v + 2, (unsigned)(uint16_t)(int16_t)off);
    tlv_rec(t, 0x0100, v, 4);
}
static void rec_id(tlv *t, uint8_t fill) {
    uint8_t v[16]; memset(v, fill, sizeof v); tlv_rec(t, 0x0001, v, 16);
}
static d2k_plan *load(const tlv *t) {
    d2k_plan *p = NULL;
    char err[200];
    if (d2k_plan_load(t->b, t->n, &p, err, sizeof err) != 0) { printf("  план: %s\n", err); return NULL; }
    return p;
}
/* HTTP-план: разрез посреди Host. */
static d2k_plan *http_split_plan(uint8_t id) {
    tlv t; tlv_begin(&t, 11); rec_id(&t, id); rec_proto(&t, 6, 4); rec_split(&t, 5, 0);
    return load(&t);
}
/* TLS-план того же вида. */
static d2k_plan *tls_split_plan(uint8_t id) {
    tlv t; tlv_begin(&t, 1); rec_id(&t, id); rec_proto(&t, 6, 1); rec_split(&t, 5, 0);
    return load(&t);
}

/* --- разбор запроса ---------------------------------------------------------- */
static void test_parse(void) {
    static const char get[] = "GET /forum/ HTTP/1.1\r\nHost: RuTracker.org\r\nAccept: */*\r\n\r\n";
    size_t off = 0, len = 0;
    CHECK(d2k_http_hello((const uint8_t *)get, sizeof get - 1, &off, &len) &&
          off == 28 && len == 13 && !memcmp(get + off, "RuTracker.org", 13),
          "обычный GET не узнан или Host не там");
    static const char port[] = "HEAD / HTTP/1.0\r\nhost:   example.com:80\r\n\r\n";
    CHECK(d2k_http_hello((const uint8_t *)port, sizeof port - 1, &off, &len) &&
          len == 11 && !memcmp(port + off, "example.com", 11), "Host с :80 и пробелами не узнан");
    static const char dot[] = "GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n";
    CHECK(d2k_http_hello((const uint8_t *)dot, sizeof dot - 1, &off, &len) && len == 11,
          "точка в конце Host не снята");
    /* Неполный заголовок (остаток в следующем сегменте) — разбирать можно,
       если строка Host целиком здесь. */
    static const char part[] = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Ag";
    CHECK(d2k_http_hello((const uint8_t *)part, sizeof part - 1, &off, &len) && len == 11,
          "первый сегмент с целой строкой Host не узнан");
    /* Любой метод запроса (keep-alive, поле 04.10): у POST тот же Host. */
    static const char post[] = "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc";
    CHECK(d2k_http_hello((const uint8_t *)post, sizeof post - 1, &off, &len) && off == 28 && len == 11,
          "POST не узнан");
    static const char *bad[] = {
        "post / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
        " GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: exam",
        "GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: exa mple.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: \r\n\r\n",
        "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
        "GET / SPDY/3\r\nHost: example.com\r\n\r\n",
        /* IP вместо имени — не имя (ревью M-2): IP-цели в своём контексте. */
        "GET / HTTP/1.1\r\nHost: 37.221.67.160\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        CHECK(!d2k_http_hello((const uint8_t *)bad[i], strlen(bad[i]), &off, &len),
              "негодный запрос принят за вход плана");
    }
    for (size_t cut = 0; cut < sizeof get - 1; cut++) {
        (void)d2k_http_hello((const uint8_t *)get, cut, &off, &len);
    }
}

/* --- план: протокол http требует своего исполнителя ------------------------ */
static void test_plan(void) {
    d2k_plan *p = http_split_plan(1);
    CHECK(p != NULL, "HTTP-план не принят");
    d2k_plan_free(p);
    tlv t; tlv_begin(&t, 10); rec_proto(&t, 6, 4); rec_split(&t, 5, 0);
    CHECK(load(&t) == NULL, "HTTP-план с minexec 10 принят: старый исполнитель применил бы его к TLS");
    tlv_begin(&t, 11); rec_proto(&t, 17, 4);
    CHECK(load(&t) == NULL, "HTTP-план поверх UDP принят");
}

/* --- таблица планов: HTTP и TLS не смешиваются ------------------------------ */
static void test_table(void) {
    d2k_plantab *tab = d2k_plantab_new(16);
    const uint8_t name[] = "rutracker.org";
    const size_t nl = sizeof name - 1;
    CHECK(d2k_plantab_set_name_family(tab, name, nl, 1, tls_split_plan(2),
                                      D2K_PLAN_SHAPE_HTTP, 0, 4) == -2,
          "TLS-план встал под формой HTTP");
    CHECK(d2k_plantab_set_name_family(tab, name, nl, 1, http_split_plan(3),
                                      D2K_PLAN_SHAPE_MODERN, 0, 4) == -2,
          "HTTP-план встал под формой TLS");
    CHECK(d2k_plantab_set_name_family(tab, name, nl, 1, http_split_plan(4),
                                      D2K_PLAN_SHAPE_GRANDFATHER, 0, 4) == -2,
          "HTTP-план встал под дедушкиным правом");
    CHECK(d2k_plantab_set_name_family(tab, name, nl, 1, http_split_plan(5),
                                      D2K_PLAN_SHAPE_HTTP, 0, 4) == 0, "HTTP-план не встал");
    const uint8_t ip[4] = {195, 82, 146, 214};
    CHECK(d2k_plantab_set_addr_shaped(tab, ip, 4, 1, tls_split_plan(6), D2K_PLAN_SHAPE_MODERN) == 0,
          "адресный TLS-план не встал");
    const d2k_plan *h = d2k_plantab_find_http(tab, name, nl, 4, 0, 2);
    CHECK(h && d2k_plan_id(h)[0] == 5, "HTTP-план имени не найден");
    const d2k_plan *t = d2k_plantab_find_target(tab, name, nl, ip, 4, 2, D2K_PLAN_SHAPE_MODERN, 0);
    CHECK(t && d2k_plan_id(t)[0] == 6,
          "HTTP-запись имени заслонила TLS-приветствию адресный план или выдала себя");
    CHECK(!d2k_plantab_find_target(tab, name, nl, NULL, 4, 2, D2K_PLAN_SHAPE_ANY, 0),
          "HTTP-план достался TLS-приветствию неизвестной формы");
    /* Дедушкина TLS-запись имени HTTP-запросу не достаётся. */
    const uint8_t other[] = "example.org";
    CHECK(d2k_plantab_set_name_family(tab, other, sizeof other - 1, 1, tls_split_plan(7),
                                      D2K_PLAN_SHAPE_GRANDFATHER, 0, 4) == 0, "дедушкина запись не встала");
    CHECK(!d2k_plantab_find_http(tab, other, sizeof other - 1, 4, 0, 3),
          "дедушкина TLS-запись досталась HTTP");
    /* Проба — только своему порту. */
    CHECK(d2k_plantab_set_name_family(tab, other, sizeof other - 1, 1, http_split_plan(8),
                                      D2K_PLAN_SHAPE_HTTP, 0x1234, 4) == 0, "HTTP-проба не встала");
    CHECK(!d2k_plantab_find_http(tab, other, sizeof other - 1, 4, 0, 3),
          "HTTP-проба досталась чужому потоку");
    const d2k_plan *pr = d2k_plantab_find_http(tab, other, sizeof other - 1, 4, 0x1234, 3);
    CHECK(pr && d2k_plan_id(pr)[0] == 8, "HTTP-проба не досталась своему порту");
    const d2k_plan *tp = d2k_plantab_find_target(tab, other, sizeof other - 1, NULL, 4, 3,
                                                 D2K_PLAN_SHAPE_ANY, 0x1234);
    CHECK(!tp || d2k_plan_proto(tp) != D2K_PLAN_PROTO_HTTP,
          "HTTP-проба досталась TLS-приветствию того же порта");
    tp = d2k_plantab_find_target(tab, other, sizeof other - 1, NULL, 4, 3,
                                 D2K_PLAN_SHAPE_MODERN, 0x1234);
    CHECK(!tp || d2k_plan_proto(tp) != D2K_PLAN_PROTO_HTTP,
          "HTTP-проба досталась TLS 1.3-приветствию того же порта");
    CHECK(!d2k_plantab_find_http(tab, name, nl, 6, 0, 3), "IPv4-план достался IPv6");
    d2k_plantab_free(tab);
}

/* ЗАПИСИ HTTP И TLS ОДНОГО ИМЕНИ СОСУЩЕСТВУЮТ (ревью I-1, воспроизведение
   rv51/gf.c): дедушкина TLS-запись имени затирала HTTP-запись, и пропадали
   оба плана. В любом порядке, и после синхронизации каталога, идущей вслед
   за загрузкой http-plans.txt. */
static int has_http(d2k_plantab *t, const uint8_t *n, size_t l, uint8_t id) {
    const d2k_plan *p = d2k_plantab_find_http(t, n, l, 4, 0, 9);
    return p && d2k_plan_id(p)[0] == id;
}
static int has_tls(d2k_plantab *t, const uint8_t *n, size_t l, uint8_t shape, uint8_t id) {
    const d2k_plan *p = d2k_plantab_find_target(t, n, l, NULL, 4, 9, shape, 0);
    return p && d2k_plan_id(p)[0] == id;
}
static void test_coexist(void) {
    static const uint8_t name[] = "fast-torrent.ru";
    const size_t nl = sizeof name - 1;
    static const uint8_t tls_shapes[] = {D2K_PLAN_SHAPE_GRANDFATHER, D2K_PLAN_SHAPE_MODERN,
                                         D2K_PLAN_SHAPE_LEGACY};
    for (size_t k = 0; k < sizeof tls_shapes; k++) {
        uint8_t sh = tls_shapes[k];
        uint8_t seen = sh == D2K_PLAN_SHAPE_GRANDFATHER ? D2K_PLAN_SHAPE_MODERN : sh;
        /* HTTP, затем TLS. */
        d2k_plantab *t = d2k_plantab_new(16);
        CHECK(d2k_plantab_set_name_family(t, name, nl, 1, http_split_plan(3), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0 &&
              d2k_plantab_set_name_family(t, name, nl, 1, tls_split_plan(2), sh, 0, 4) == 0,
              "HTTP, затем TLS: установка отказала");
        CHECK(has_http(t, name, nl, 3), "TLS-запись затёрла HTTP-запись имени");
        CHECK(has_tls(t, name, nl, seen, 2), "TLS-план имени пропал рядом с HTTP-записью");
        d2k_plantab_free(t);
        /* TLS, затем HTTP. */
        t = d2k_plantab_new(16);
        CHECK(d2k_plantab_set_name_family(t, name, nl, 1, tls_split_plan(2), sh, 0, 4) == 0 &&
              d2k_plantab_set_name_family(t, name, nl, 1, http_split_plan(3), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
              "TLS, затем HTTP: установка отказала");
        CHECK(has_http(t, name, nl, 3) && has_tls(t, name, nl, seen, 2),
              "HTTP-запись затёрла TLS-запись имени или пропала сама");
        d2k_plantab_free(t);
    }
    /* Запуск d2kc: http-plans.txt, затем синхронизация каталога (TLS 1.3 и
       дедушкина — по существующему правилу дедушкина обновляет план
       измеренной TLS-записи, своей не заводит), затем повторная постановка
       HTTP-планов. */
    d2k_plantab *t = d2k_plantab_new(16);
    CHECK(d2k_plantab_set_name_family(t, name, nl, 1, http_split_plan(3), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0 &&
          d2k_plantab_set_name_family(t, name, nl, 2, tls_split_plan(4), D2K_PLAN_SHAPE_MODERN, 0, 4) == 0 &&
          d2k_plantab_set_name_family(t, name, nl, 3, tls_split_plan(5), D2K_PLAN_SHAPE_GRANDFATHER, 0, 4) == 0 &&
          d2k_plantab_set_name_family(t, name, nl, 4, http_split_plan(6), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "запуск: установка отказала");
    CHECK(has_http(t, name, nl, 6), "после синхронизации каталога HTTP-план не тот");
    CHECK(has_tls(t, name, nl, D2K_PLAN_SHAPE_MODERN, 5), "после синхронизации TLS-план не тот");
    d2k_plantab_free(t);
    /* Снятие одного не трогает другое. */
    t = d2k_plantab_new(16);
    CHECK(d2k_plantab_set_name_family(t, name, nl, 1, http_split_plan(3), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0 &&
          d2k_plantab_set_name_family(t, name, nl, 2, tls_split_plan(5), D2K_PLAN_SHAPE_GRANDFATHER, 0, 4) == 0,
          "установка отказала");
    CHECK(d2k_plantab_del_name_shaped(t, name, nl, 6, D2K_PLAN_SHAPE_GRANDFATHER, 4) == 1 &&
          has_http(t, name, nl, 3) && !has_tls(t, name, nl, D2K_PLAN_SHAPE_LEGACY, 5),
          "снятие дедушкиной TLS-записи тронуло HTTP-запись");
    CHECK(d2k_plantab_set_name_family(t, name, nl, 3, tls_split_plan(7), D2K_PLAN_SHAPE_MODERN, 0, 4) == 0 &&
          d2k_plantab_del_name_shaped(t, name, nl, 6, D2K_PLAN_SHAPE_HTTP, 4) == 1 &&
          has_tls(t, name, nl, D2K_PLAN_SHAPE_MODERN, 7) && !has_http(t, name, nl, 3),
          "снятие HTTP-записи тронуло TLS-запись");
    d2k_plantab_free(t);
}

/* --- сессия: разрез запроса на проводе -------------------------------------- */
static unsigned g_sport = 80;
static size_t pkt4(uint8_t *o, int to_server, uint8_t flags, uint32_t seq, uint32_t ack,
                   const char *pay) {
    size_t pl = pay ? strlen(pay) : 0, n = 40 + pl;
    memset(o, 0, n);
    o[0] = 0x45; wr16(o + 2, (unsigned)n); o[8] = 64; o[9] = 6;
    const uint8_t c[4] = {192, 168, 1, 117}, s[4] = {195, 82, 146, 214};
    memcpy(o + 12, to_server ? c : s, 4); memcpy(o + 16, to_server ? s : c, 4);
    wr16(o + 20, to_server ? 51000 : g_sport); wr16(o + 22, to_server ? g_sport : 51000);
    wr32(o + 24, seq); wr32(o + 28, ack); o[32] = 0x50; o[33] = flags; wr16(o + 34, 64240);
    if (pl) { memcpy(o + 40, pay, pl); }
    return n;
}

static const char GET[] = "GET /forum/ HTTP/1.1\r\nHost: rutracker.org\r\nAccept: */*\r\n\r\n";

static void run_flow(d2k_session *s, const char *req, d2k_result *res) {
    static uint8_t p[2048], out[16384];
    d2k_result r;
    size_t n = pkt4(p, 1, 0x02, 1000, 0, NULL);
    d2k_session_packet(s, p, n, 10, out, sizeof out, &r);
    n = pkt4(p, 0, 0x12, 5000, 1001, NULL);
    d2k_session_packet(s, p, n, 20, out, sizeof out, &r);
    n = pkt4(p, 1, 0x18, 1001, 5001, req);
    d2k_session_packet(s, p, n, 30, out, sizeof out, res);
}

static size_t count_kind(const d2k_session *s, uint8_t kind) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t c = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind) { c++; }
    }
    return c;
}

static void test_session(void) {
    d2k_session *s = d2k_session_new(64, 64);
    const uint8_t name[] = "rutracker.org";
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      http_split_plan(9), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал в сессию");
    d2k_result r;
    run_flow(s, GET, &r);
    CHECK(r.applied && r.n_out == 2 && r.verdict == D2K_VERDICT_DROP,
          "HTTP-план не исполнен разрезом запроса");
    if (r.n_out == 2) {
        size_t host = (size_t)(strstr(GET, "rutracker.org") - GET);
        size_t mid = host + 13 / 2;
        static uint8_t out[16384];
        (void)out;
        CHECK(r.out[0].len == 40 + mid && r.out[1].len == 40 + strlen(GET) - mid,
              "разрез не посреди Host");
    }
    CHECK(count_kind(s, D2K_JRN_PLAN_APPLIED) == 1, "исполнение HTTP-плана не сообщено");
    CHECK(count_kind(s, D2K_JRN_HELLO_SNI) == 0 && count_kind(s, D2K_JRN_SUSPECT) == 0,
          "HTTP-поток породил TLS-события");
    d2k_session_free(s);

    /* У имени только TLS-план: HTTP-запрос идёт как есть. */
    s = d2k_session_new(64, 64);
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      tls_split_plan(10), D2K_PLAN_SHAPE_MODERN, 0, 4) == 0,
          "TLS-план не встал");
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      tls_split_plan(11), D2K_PLAN_SHAPE_GRANDFATHER, 0, 4) == 0,
          "дедушкин TLS-план не встал");
    run_flow(s, GET, &r);
    CHECK(!r.applied && r.n_out == 0 && r.verdict == D2K_VERDICT_ACCEPT,
          "TLS-план применён к HTTP-запросу");
    d2k_session_free(s);

    /* Запрос без Host — как есть, даже при HTTP-плане имени. POST с Host —
       тот же вход, что GET (keep-alive, поле 04.10: коробка смотрит каждый
       запрос, не только GET). */
    s = d2k_session_new(64, 64);
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      http_split_plan(12), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал");
    run_flow(s, "POST /x HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 0\r\n\r\n", &r);
    CHECK(r.applied && r.n_out == 2, "POST с Host не получил HTTP-план");
    d2k_session_free(s);
    s = d2k_session_new(64, 64);
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      http_split_plan(12), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал");
    run_flow(s, "POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n", &r);
    CHECK(!r.applied && r.verdict == D2K_VERDICT_ACCEPT, "запрос без Host изменён HTTP-планом");
    /* Не порт 80 (ревью M-1): Host без порта означает 80, а поток идёт не
       туда — не наш вход. */
    g_sport = 8080;
    run_flow(s, GET, &r);
    CHECK(!r.applied && r.verdict == D2K_VERDICT_ACCEPT, "запрос не на порт 80 изменён HTTP-планом");
    g_sport = 80;
    d2k_session_free(s);
    (void)rd32;

    /* Приманка-запрос с испорченной суммой перед разрезом. */
    s = d2k_session_new(64, 64);
    {
        static const char fake[] = "GET / HTTP/1.1\r\nHost: disk.rzd.ru\r\n\r\n";
        tlv t; tlv_begin(&t, 11); rec_id(&t, 13); rec_proto(&t, 6, 4);
        uint8_t pv[64]; wr16(pv, 1); memcpy(pv + 2, fake, sizeof fake - 1);
        tlv_rec(&t, 0x0010, pv, 2 + sizeof fake - 1);
        uint8_t po[8] = {0, 1, 0, 1, 0, 0, 0, 0};      /* id 1, badsum */
        tlv_rec(&t, 0x0011, po, 8);
        uint8_t fk[10] = {0, 1, 0, 1, 1, 0, 0, 0, 0, 0}; /* payload 1, poison 1, x1, before */
        tlv_rec(&t, 0x0101, fk, 10);
        rec_split(&t, 5, 0);
        d2k_plan *fp = load(&t);
        CHECK(fp && d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                                fp, D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
              "HTTP-план с приманкой не встал");
        static uint8_t p[2048], out[16384];
        d2k_result rr;
        size_t n = pkt4(p, 1, 0x02, 1000, 0, NULL);
        d2k_session_packet(s, p, n, 10, out, sizeof out, &rr);
        n = pkt4(p, 0, 0x12, 5000, 1001, NULL);
        d2k_session_packet(s, p, n, 20, out, sizeof out, &rr);
        n = pkt4(p, 1, 0x18, 1001, 5001, GET);
        d2k_session_packet(s, p, n, 30, out, sizeof out, &rr);
        CHECK(rr.applied && rr.n_out == 3, "приманка + разрез не исполнены");
        if (rr.n_out == 3) {
            CHECK(rr.out[0].len == 40 + sizeof fake - 1 &&
                  !memcmp(out + rr.out[0].off + 40, fake, sizeof fake - 1) &&
                  !d2k_wire_tcp_checksum_ok(out + rr.out[0].off, rr.out[0].len),
                  "приманка не первой или сумма у неё не испорчена");
            CHECK(d2k_wire_tcp_checksum_ok(out + rr.out[1].off, rr.out[1].len) &&
                  d2k_wire_tcp_checksum_ok(out + rr.out[2].off, rr.out[2].len),
                  "куски запроса с испорченной суммой");
        }
    }
    d2k_session_free(s);

    /* Пробный план — только зонду своего порта. */
    s = d2k_session_new(64, 64);
    {
        uint8_t port_be[2] = {51000 >> 8, 51000 & 255};
        uint16_t sport;
        memcpy(&sport, port_be, 2);
        CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                          http_split_plan(14), D2K_PLAN_SHAPE_HTTP, sport, 4) == 0,
              "HTTP-проба не встала");
        run_flow(s, GET, &r);
        CHECK(!r.applied, "пробный HTTP-план достался обычному потоку");
        static uint8_t p[2048], out[16384];
        d2k_result rr;
        size_t n = pkt4(p, 1, 0x02, 7000, 0, NULL);
        d2k_session_packet_probe(s, p, n, 40, out, sizeof out, &rr);
        n = pkt4(p, 0, 0x12, 9000, 7001, NULL);
        d2k_session_packet(s, p, n, 50, out, sizeof out, &rr);
        n = pkt4(p, 1, 0x18, 7001, 9001, GET);
        d2k_session_packet_probe(s, p, n, 60, out, sizeof out, &rr);
        CHECK(rr.applied && rr.n_out == 2 && d2k_plan_id(NULL) == NULL && rr.plan_id[0] == 14,
              "пробный HTTP-план не исполнен на зонде своего порта");
    }
    d2k_session_free(s);
}

/* --- KEEP-ALIVE: КАЖДЫЙ ЗАПРОС СОЕДИНЕНИЯ (поле 04.10.2026) -----------------
 *
 * Safari, www.fast-torrent.ru, ER-Telecom: первый запрос соединения получил
 * план и ответ 200, второй запрос на том же соединении (GET /False/) — вставку
 * провайдера 302 → lawfilter. Коробка смотрит каждый запрос. Граница запроса —
 * из потока клиента: конец заголовка + Content-Length; запрос не с начала
 * сегмента, пропущенная граница, неизвестный конец — как есть, со счётом. */

/* Пакет клиент↔сервер с произвольными портами клиента и сервера. */
static size_t pkt_ka(uint8_t *o, int to_server, uint8_t flags, uint32_t seq, uint32_t ack,
                     const char *pay, size_t pl, unsigned sport) {
    size_t n = 40 + pl;
    memset(o, 0, n);
    o[0] = 0x45; wr16(o + 2, (unsigned)n); o[8] = 64; o[9] = 6;
    const uint8_t c[4] = {192, 168, 1, 67}, sv[4] = {37, 221, 67, 160};
    memcpy(o + 12, to_server ? c : sv, 4); memcpy(o + 16, to_server ? sv : c, 4);
    wr16(o + 20, to_server ? 58305 : sport); wr16(o + 22, to_server ? sport : 58305);
    wr32(o + 24, seq); wr32(o + 28, ack); o[32] = 0x50; o[33] = flags; wr16(o + 34, 2048);
    if (pl) { memcpy(o + 40, pay, pl); }
    return n;
}

typedef struct {
    d2k_session *s;
    uint32_t cseq, sseq;      /* следующий байт клиента и сервера */
    unsigned sport;
    uint64_t now;
    uint8_t out[16384];
    d2k_result r;
} ka_flow;

static void ka_open(ka_flow *k, uint32_t cisn, uint32_t sisn, unsigned sport) {
    uint8_t p[256];
    k->cseq = cisn + 1; k->sseq = sisn + 1; k->sport = sport; k->now = 10;
    size_t n = pkt_ka(p, 1, 0x02, cisn, 0, NULL, 0, sport);
    d2k_session_packet(k->s, p, n, k->now++, k->out, sizeof k->out, &k->r);
    n = pkt_ka(p, 0, 0x12, sisn, k->cseq, NULL, 0, sport);
    d2k_session_packet(k->s, p, n, k->now++, k->out, sizeof k->out, &k->r);
    n = pkt_ka(p, 1, 0x10, k->cseq, k->sseq, NULL, 0, sport);
    d2k_session_packet(k->s, p, n, k->now++, k->out, sizeof k->out, &k->r);
}

/* Нагрузка клиента с текущего номера (или с данного), номер двигается. */
static d2k_result *ka_send_at(ka_flow *k, uint32_t seq, const char *pay, size_t pl) {
    static uint8_t p[4096];
    size_t n = pkt_ka(p, 1, 0x18, seq, k->sseq, pay, pl, k->sport);
    d2k_session_packet(k->s, p, n, k->now++, k->out, sizeof k->out, &k->r);
    if (k->r.applied) {
        /* Как d2kd: отчёт о каждой посылке и о вердикте оригинала. */
        for (size_t i = 0; i <= k->r.n_out; i++) {
            d2k_session_sent(k->s, k->now, &k->r.key, k->r.execution_id);
        }
    }
    if ((int32_t)(seq + (uint32_t)pl - k->cseq) > 0) { k->cseq = seq + (uint32_t)pl; }
    return &k->r;
}
static d2k_result *ka_send(ka_flow *k, const char *pay) {
    return ka_send_at(k, k->cseq, pay, strlen(pay));
}

/* Ответ сервера (len байт) и чистый ACK клиента. */
static void ka_answer(ka_flow *k, size_t len) {
    static uint8_t p[2048];
    static char body[1400];
    memset(body, 'x', sizeof body);
    memcpy(body, "HTTP/1.1 200 OK\r\n", 17);
    while (len) {
        size_t c = len > sizeof body ? sizeof body : len;
        size_t n = pkt_ka(p, 0, 0x18, k->sseq, k->cseq, body, c, k->sport);
        d2k_session_packet(k->s, p, n, k->now++, k->out, sizeof k->out, &k->r);
        CHECK(!k->r.applied && k->r.verdict == D2K_VERDICT_ACCEPT, "ответ сервера тронут");
        k->sseq += (uint32_t)c; len -= c;
    }
    size_t n = pkt_ka(p, 1, 0x10, k->cseq, k->sseq, NULL, 0, k->sport);
    d2k_session_packet(k->s, p, n, k->now++, k->out, sizeof k->out, &k->r);
}

/* Посылка i результата: номер, подтверждение, нагрузка, сумма. */
static uint32_t o_seq(const ka_flow *k, size_t i) { return rd32(k->out + k->r.out[i].off + 24); }
static uint32_t o_ack(const ka_flow *k, size_t i) { return rd32(k->out + k->r.out[i].off + 28); }
static const uint8_t *o_pay(const ka_flow *k, size_t i) { return k->out + k->r.out[i].off + 40; }
static size_t o_len(const ka_flow *k, size_t i) { return k->r.out[i].len - 40; }
static int o_sum(const ka_flow *k, size_t i) {
    return d2k_wire_tcp_checksum_ok(k->out + k->r.out[i].off, k->r.out[i].len);
}

/* Разрез посреди Host: два куска, номера от начала ЭТОГО запроса, оба с
   подтверждением этого пакета, байты — сам запрос. */
static int ka_split_ok(const ka_flow *k, uint32_t seq, const char *req) {
    size_t rl = strlen(req);
    const char *h = strstr(req, "\r\nHost: ");
    if (!h || k->r.n_out != 2 || !k->r.applied || k->r.verdict != D2K_VERDICT_DROP) { return 0; }
    size_t host = (size_t)(h - req) + 8, hl = strcspn(req + host, "\r");
    size_t mid = host + hl / 2;
    return o_seq(k, 0) == seq && o_len(k, 0) == mid && !memcmp(o_pay(k, 0), req, mid) &&
           o_seq(k, 1) == seq + (uint32_t)mid && o_len(k, 1) == rl - mid &&
           !memcmp(o_pay(k, 1), req + mid, rl - mid) &&
           o_ack(k, 0) == k->sseq && o_ack(k, 1) == k->sseq && o_sum(k, 0) && o_sum(k, 1);
}

static d2k_session *ka_session(d2k_plan *p, const char *name) {
    d2k_session *s = d2k_session_new(64, 64);
    CHECK(p && d2k_plantab_set_name_family(d2k_session_plans(s), (const uint8_t *)name,
                                           strlen(name), 1, p, D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал");
    return s;
}

static d2k_payload_stats ka_stats(const d2k_session *s) {
    d2k_payload_stats ps;
    d2k_session_payload_stats(s, &ps);
    return ps;
}

static const char REQ1[] = "GET / HTTP/1.1\r\nHost: rutracker.org\r\nConnection: keep-alive\r\n\r\n";
static const char REQ2[] = "GET /forum/viewforum.php?f=7 HTTP/1.1\r\nHost: rutracker.org\r\n"
                           "Referer: http://rutracker.org/\r\nConnection: keep-alive\r\n\r\n";
static const char REQ3[] = "HEAD /favicon.ico HTTP/1.1\r\nHost: rutracker.org\r\n\r\n";

static void test_keepalive_split(void) {
    ka_flow k;
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(20), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    uint32_t at = k.cseq;
    ka_send(&k, REQ1);
    CHECK(ka_split_ok(&k, at, REQ1), "первый запрос соединения не разрезан");
    ka_answer(&k, 3000);
    at = k.cseq;
    ka_send(&k, REQ2);
    CHECK(ka_split_ok(&k, at, REQ2), "второй запрос соединения не получил план (поле 04.10)");
    ka_answer(&k, 500);
    at = k.cseq;
    ka_send(&k, REQ3);
    CHECK(ka_split_ok(&k, at, REQ3), "третий запрос соединения не получил план");
    CHECK(k.r.execution_id != 0, "исполнение третьего запроса без номера");
    CHECK(count_kind(k.s, D2K_JRN_PLAN_APPLIED) == 3, "исполнение каждого запроса не сообщено");
    CHECK(count_kind(k.s, D2K_JRN_HELLO_SNI) == 0 && count_kind(k.s, D2K_JRN_SUSPECT) == 0,
          "keep-alive HTTP породил TLS-события");
    d2k_payload_stats ps = ka_stats(k.s);
    CHECK(ps.http_later == 2 && ps.http_unaligned == 0 && ps.http_open_end == 0,
          "счётчики следующих запросов не те");
    /* Посылки прошлого запроса не отчитались — следующий как есть. */
    {
        ka_flow q;
        memset(&q, 0, sizeof q);
        q.s = ka_session(http_split_plan(19), "rutracker.org");
        ka_open(&q, 1000, 5000, 80);
        static uint8_t p[512];
        size_t n = pkt_ka(p, 1, 0x18, q.cseq, q.sseq, REQ1, strlen(REQ1), 80);
        d2k_session_packet(q.s, p, n, q.now++, q.out, sizeof q.out, &q.r);
        CHECK(q.r.applied, "первый запрос не исполнен");
        q.cseq += (uint32_t)strlen(REQ1);
        ka_answer(&q, 100);
        ka_send(&q, REQ2);
        CHECK(!q.r.applied && q.r.verdict == D2K_VERDICT_ACCEPT,
              "второй запрос исполнен поверх неотчитавшегося первого");
        d2k_session_free(q.s);
    }
    /* Повтор уже обработанного запроса — не граница: как есть, без счёта. */
    ka_send_at(&k, at, REQ3, strlen(REQ3));
    CHECK(!k.r.applied && k.r.verdict == D2K_VERDICT_ACCEPT, "повтор запроса обработан вторично");
    CHECK(ka_stats(k.s).http_unaligned == 0, "повтор запроса посчитан как сбой границы");
    d2k_session_free(k.s);
}

/* Номер переходит через 2^32 между запросами. */
static void test_keepalive_wrap(void) {
    ka_flow k;
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(21), "rutracker.org");
    ka_open(&k, 0xFFFFFFF0u, 0xFFFFFF00u, 80);
    ka_send(&k, REQ1);
    CHECK(k.r.applied, "первый запрос у края номеров не исполнен");
    ka_answer(&k, 1000);
    uint32_t at = k.cseq;
    CHECK(at < 0x1000u, "проверка не переходит через 2^32");
    ka_send(&k, REQ2);
    CHECK(ka_split_ok(&k, at, REQ2), "второй запрос за переходом номеров через ноль не разрезан");
    d2k_session_free(k.s);
}

/* План с приманкой: свой яд у каждой. */
static d2k_plan *http_fake_plan(uint8_t id, uint8_t flags, int32_t shift) {
    static const char fake[] = "GET / HTTP/1.1\r\nHost: disk.rzd.ru\r\n\r\n";
    tlv t; tlv_begin(&t, 11); rec_id(&t, id); rec_proto(&t, 6, 4);
    uint8_t pv[64]; wr16(pv, 1); memcpy(pv + 2, fake, sizeof fake - 1);
    tlv_rec(&t, 0x0010, pv, 2 + sizeof fake - 1);
    uint8_t po[8] = {0, 1, 0, flags, 0, 0, 0, 0};
    wr32(po + 4, (uint32_t)shift);
    tlv_rec(&t, 0x0011, po, 8);
    uint8_t fk[10] = {0, 1, 0, 1, 1, 0, 0, 0, 0, 0}; /* приманка 1, яд 1, x1, перед */
    tlv_rec(&t, 0x0101, fk, 10);
    rec_split(&t, 5, 0);
    return load(&t);
}

static void test_keepalive_fakes(void) {
    /* badsum: приманка с номером ЭТОГО запроса и подтверждением ЭТОГО пакета. */
    ka_flow k;
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_fake_plan(22, 1, 0), "rutracker.org");
    ka_open(&k, 70000, 9000, 80);
    ka_send(&k, REQ1);
    CHECK(k.r.applied && k.r.n_out == 3, "первый запрос: приманка + разрез не исполнены");
    ka_answer(&k, 2800);
    uint32_t at = k.cseq;
    ka_send(&k, REQ2);
    CHECK(k.r.applied && k.r.n_out == 3, "второй запрос: приманка + разрез не исполнены");
    if (k.r.n_out == 3) {
        CHECK(o_seq(&k, 0) == at && o_ack(&k, 0) == k.sseq && !o_sum(&k, 0) &&
              !memcmp(o_pay(&k, 0), "GET / HTTP/1.1\r\nHost: disk.rzd.ru", 33),
              "приманка второго запроса не на его номере, не с его подтверждением или с верной суммой");
        CHECK(o_seq(&k, 1) == at && o_sum(&k, 1) && o_sum(&k, 2) &&
              o_seq(&k, 2) == at + (uint32_t)o_len(&k, 1) &&
              o_len(&k, 1) + o_len(&k, 2) == strlen(REQ2) &&
              o_ack(&k, 1) == k.sseq && o_ack(&k, 2) == k.sseq,
              "куски второго запроса не там");
    }
    d2k_session_free(k.s);

    /* seqshift −66000: приманка за окном назад от ТЕКУЩЕГО номера, а не от
       начала потока; поток уже дальше 66000 байт клиента. */
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_fake_plan(23, 0, -66000), "rutracker.org");
    ka_open(&k, 1000, 9000, 80);
    ka_send(&k, REQ1);
    CHECK(k.r.applied && k.r.n_out == 3 && o_seq(&k, 0) == 1001u - 66000u,
          "первый запрос: приманка не сдвинута на −66000");
    ka_answer(&k, 100);
    /* Тело POST в 70000 байт между запросами: граница по Content-Length. */
    static char post[160];
    snprintf(post, sizeof post, "POST /upload HTTP/1.1\r\nHost: rutracker.org\r\n"
             "Content-Length: 70000\r\n\r\n");
    uint32_t pat = k.cseq;
    ka_send(&k, post);
    CHECK(k.r.applied && k.r.n_out == 3 && o_seq(&k, 0) == pat - 66000u,
          "POST с телом: приманка не от его номера");
    static char chunk[1400];
    memset(chunk, 'b', sizeof chunk);
    size_t left = 70000;
    while (left) {
        size_t c = left > sizeof chunk ? sizeof chunk : left;
        ka_send_at(&k, k.cseq, chunk, c);
        CHECK(!k.r.applied && k.r.verdict == D2K_VERDICT_ACCEPT, "тело POST тронуто планом");
        left -= c;
    }
    ka_answer(&k, 200);
    uint32_t at2 = k.cseq;
    ka_send(&k, REQ2);
    CHECK(k.r.applied && k.r.n_out == 3, "запрос после тела POST не получил план");
    if (k.r.n_out == 3) {
        CHECK(o_seq(&k, 0) == at2 - 66000u && o_sum(&k, 0) && o_ack(&k, 0) == k.sseq,
              "приманка после тела POST не на −66000 от этого запроса");
        CHECK(o_seq(&k, 1) == at2 && o_seq(&k, 2) == at2 + (uint32_t)o_len(&k, 1),
              "куски запроса после тела POST не на его номерах");
    }
    d2k_payload_stats ps = ka_stats(k.s);
    CHECK(ps.http_later == 2 && ps.http_unaligned == 0, "счётчики после POST с телом не те");
    d2k_session_free(k.s);
}

/* Запрос не с начала сегмента и потерянная граница — как есть, со счётом. */
static void test_keepalive_doubt(void) {
    /* Конвейер: два запроса в одном сегменте. Первый — с начала сегмента и
       получает план; второй внутри сегмента не защищён, граница дальше
       неизвестна — третий запрос идёт как есть. */
    ka_flow k;
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(24), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    static char two[512];
    snprintf(two, sizeof two, "%s%s", REQ1, REQ3);
    uint32_t at = k.cseq;
    ka_send(&k, two);
    CHECK(k.r.applied && o_seq(&k, 0) == at, "первый запрос конвейера не получил план");
    ka_answer(&k, 300);
    ka_send(&k, REQ2);
    CHECK(!k.r.applied && k.r.verdict == D2K_VERDICT_ACCEPT && k.r.n_out == 0,
          "запрос после неразобранного конвейера изменён");
    CHECK(ka_stats(k.s).http_unaligned == 1, "конвейер не посчитан");
    d2k_session_free(k.s);

    /* Пропущенный сегмент: следующий виденный запрос дальше границы. */
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(25), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    ka_send(&k, REQ1);
    ka_answer(&k, 300);
    k.cseq += 50;            /* 50 байт клиента очередь не видела */
    ka_send(&k, REQ2);
    CHECK(!k.r.applied && k.r.verdict == D2K_VERDICT_ACCEPT, "запрос за потерянной границей изменён");
    ka_answer(&k, 300);
    ka_send(&k, REQ3);
    CHECK(!k.r.applied, "после потери границы следующий запрос изменён");
    CHECK(ka_stats(k.s).http_unaligned == 1, "потерянная граница не посчитана (или посчитана дважды)");
    d2k_session_free(k.s);

    /* Сегмент через границу: хвост тела и следующий запрос в одном сегменте. */
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(26), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    ka_send(&k, "POST /x HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 5\r\n\r\n");
    CHECK(k.r.applied, "POST с телом в следующем сегменте не получил план");
    static char tail[256];
    snprintf(tail, sizeof tail, "abcde%s", REQ3);
    ka_send(&k, tail);
    CHECK(!k.r.applied && k.r.verdict == D2K_VERDICT_ACCEPT, "запрос не с начала сегмента изменён");
    CHECK(ka_stats(k.s).http_unaligned == 1, "запрос не с начала сегмента не посчитан");
    d2k_session_free(k.s);

    /* На границе не запрос (например, протокол после Upgrade без заголовка). */
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(27), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    ka_send(&k, REQ1);
    ka_answer(&k, 100);
    ka_send(&k, "\x81\x85garbage-frame");
    CHECK(!k.r.applied, "не запрос на границе изменён");
    ka_send(&k, REQ3);
    CHECK(!k.r.applied, "запрос после не-запроса на границе изменён");
    CHECK(ka_stats(k.s).http_unaligned == 1, "не-запрос на границе не посчитан");
    d2k_session_free(k.s);

    /* Конец запроса неизвестен: chunked — дальше как есть, счёт отдельный. */
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(28), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    ka_send(&k, "POST /x HTTP/1.1\r\nHost: rutracker.org\r\nTransfer-Encoding: chunked\r\n\r\n"
                "5\r\nabcde\r\n0\r\n\r\n");
    CHECK(k.r.applied, "chunked POST с начала потока не получил план");
    ka_answer(&k, 100);
    ka_send(&k, REQ3);
    CHECK(!k.r.applied, "запрос после chunked изменён: граница выдумана");
    d2k_payload_stats ps = ka_stats(k.s);
    CHECK(ps.http_open_end == 1 && ps.http_unaligned == 0, "неизвестный конец запроса не посчитан");
    d2k_session_free(k.s);

    /* Заголовок первого запроса не кончился в сегменте — граница неизвестна. */
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_split_plan(29), "rutracker.org");
    ka_open(&k, 1000, 5000, 80);
    ka_send(&k, "GET / HTTP/1.1\r\nHost: rutracker.org\r\nCookie: aaaa");
    CHECK(k.r.applied, "первый сегмент с целым Host не получил план");
    ka_send(&k, "bbbb\r\n\r\n");
    CHECK(!k.r.applied, "продолжение заголовка изменено");
    ka_answer(&k, 100);
    ka_send(&k, REQ3);
    CHECK(!k.r.applied, "запрос после заголовка в двух сегментах изменён");
    CHECK(ka_stats(k.s).http_open_end == 1, "заголовок в двух сегментах не посчитан");
    d2k_session_free(k.s);
}

/* TLS не затронут: ни поток TLS с запросоподобными байтами позже, ни
   открытый текст на 443; HTTP-план имени им не достаётся. */
static void test_keepalive_tls(void) {
    d2k_session *s = d2k_session_new(64, 64);
    const uint8_t name[] = "rutracker.org";
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      http_split_plan(30), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал");
    ka_flow k;
    memset(&k, 0, sizeof k);
    k.s = s;
    /* Открытый текст на 443: не порт 80 — ни первый, ни следующий запрос. */
    ka_open(&k, 1000, 5000, 443);
    ka_send(&k, REQ1);
    CHECK(!k.r.applied, "запрос на 443 изменён HTTP-планом");
    ka_answer(&k, 100);
    ka_send(&k, REQ2);
    CHECK(!k.r.applied, "второй запрос на 443 изменён HTTP-планом");
    d2k_session_free(s);

    /* TLS-приветствие на 80 (TLS на нестандартном порту): поток TLS, байты
       позже, похожие на запрос, не трогаются. */
    s = d2k_session_new(64, 64);
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      http_split_plan(31), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал");
    memset(&k, 0, sizeof k);
    k.s = s;
    ka_open(&k, 1000, 5000, 80);
    static const uint8_t hello_head[] = {0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00};
    ka_send_at(&k, k.cseq, (const char *)hello_head, sizeof hello_head);
    CHECK(!k.r.applied, "TLS-начало на 80 изменено HTTP-планом");
    ka_answer(&k, 100);
    ka_send(&k, REQ2);
    CHECK(!k.r.applied && k.r.verdict == D2K_VERDICT_ACCEPT,
          "запросоподобные байты не-HTTP потока изменены HTTP-планом");
    d2k_payload_stats ps = ka_stats(s);
    CHECK(ps.http_later == 0 && ps.http_unaligned == 0, "не-HTTP поток посчитан как HTTP");
    d2k_session_free(s);
}

/* Захват 04.10.2026 (s2-fasttorrent.pcap, Safari): номера и запросы как на
   проводе, значения кук заменены той же длины. GET / — 426 байт с ISN+1,
   ответ 24857 байт, GET /False/ — 516 байт с ISN+427, подтверждение
   2370669039. На нём пришла вставка 302 → lawfilter. */
static const char CAP1[] =
    "GET / HTTP/1.1\r\nHost: www.fast-torrent.ru\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X "
    "10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15\r\n"
    "Upgrade-Insecure-Requests: 1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,"
    "*/*;q=0.8\r\nAccept-Language: ru\r\nPriority: u=0, i\r\nAccept-Encoding: gzip, deflate\r\n"
    "Cookie: csrftoken=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\nConnection: keep-alive\r\n\r\n";
static const char CAP2[] =
    "GET /False/ HTTP/1.1\r\nHost: www.fast-torrent.ru\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac "
    "OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15\r\n"
    "Accept: image/webp,image/avif,image/jxl,image/heic,image/heic-sequence,video/*;q=0.8,image/png,"
    "image/svg+xml,image/*;q=0.8,*/*;q=0.5\r\nAccept-Language: ru\r\nReferer: http://www.fast-torrent.ru/"
    "\r\nPriority: u=5, i\r\nAccept-Encoding: gzip, deflate\r\nCookie: aaaaaaaaaaa=1; "
    "csrftoken=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\r\nConnection: keep-alive\r\n\r\n";

static void test_keepalive_capture(void) {
    CHECK(strlen(CAP1) == 426 && strlen(CAP2) == 516, "запросы захвата не той длины");
    ka_flow k;
    memset(&k, 0, sizeof k);
    k.s = ka_session(http_fake_plan(32, 1, 0), "www.fast-torrent.ru");
    ka_open(&k, 1986579867u, 2370644181u, 80);
    ka_send(&k, CAP1);
    CHECK(k.r.applied && k.r.n_out == 3 && o_seq(&k, 0) == 1986579868u &&
          o_seq(&k, 2) == 1986579868u + 31u, "GET / захвата: план не тот (разрез на 31, как на проводе)");
    ka_answer(&k, 24857);
    CHECK(k.sseq == 2370669039u && k.cseq == 1986580294u, "номера захвата не сошлись");
    ka_send(&k, CAP2);
    CHECK(k.r.applied && k.r.n_out == 3, "GET /False/ захвата не получил план — поле 04.10");
    if (k.r.n_out == 3) {
        CHECK(o_seq(&k, 0) == 1986580294u && o_ack(&k, 0) == 2370669039u && !o_sum(&k, 0),
              "приманка GET /False/: номер/подтверждение/сумма не те");
        CHECK(o_seq(&k, 1) == 1986580294u && o_len(&k, 1) == 37 &&
              o_seq(&k, 2) == 1986580294u + 37u && o_len(&k, 2) == 516 - 37 &&
              o_ack(&k, 1) == 2370669039u && o_ack(&k, 2) == 2370669039u &&
              o_sum(&k, 1) && o_sum(&k, 2) &&
              !memcmp(o_pay(&k, 1), CAP2, 37) && !memcmp(o_pay(&k, 2), CAP2 + 37, 516 - 37),
              "куски GET /False/ не посреди Host или не на номерах захвата");
    }
    d2k_session_free(k.s);
}

int main(void) {
    test_parse();
    test_plan();
    test_table();
    test_coexist();
    test_session();
    test_keepalive_split();
    test_keepalive_wrap();
    test_keepalive_fakes();
    test_keepalive_doubt();
    test_keepalive_tls();
    test_keepalive_capture();
    if (fails) { printf("test_http_hello: провалов %d\n", fails); return 1; }
    printf("test_http_hello: все проверки прошли\n");
    return 0;
}
