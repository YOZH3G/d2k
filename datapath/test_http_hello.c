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
    static const char *bad[] = {
        "POST / HTTP/1.1\r\nHost: example.com\r\n\r\n",
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

    /* Запрос без Host или POST — как есть, даже при HTTP-плане имени. */
    s = d2k_session_new(64, 64);
    CHECK(d2k_plantab_set_name_family(d2k_session_plans(s), name, sizeof name - 1, 1,
                                      http_split_plan(12), D2K_PLAN_SHAPE_HTTP, 0, 4) == 0,
          "HTTP-план не встал");
    run_flow(s, "POST /x HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 0\r\n\r\n", &r);
    CHECK(!r.applied && r.verdict == D2K_VERDICT_ACCEPT, "POST изменён HTTP-планом");
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

int main(void) {
    test_parse();
    test_plan();
    test_table();
    test_coexist();
    test_session();
    if (fails) { printf("test_http_hello: провалов %d\n", fails); return 1; }
    printf("test_http_hello: все проверки прошли\n");
    return 0;
}
