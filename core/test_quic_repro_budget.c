/* test_quic_repro_budget.c — воспроизведение обрыва QUIC своим запросом
 * мерится бюджетом коробки (поле 04.10, rua.gr в Safari).
 *
 * Коробка рвёт поток после бюджета пакетов (у QUIC 04.10 — 14–17 пакетов
 * сервера), а свой запрос «/» у короткой страницы заканчивался ВНУТРИ
 * бюджета: ответ целиком — «обрыв не воспроизвёлся», d2kc говорил
 * «проходит как есть», пока Safari стоял. Теперь, как у подтверждений
 * задачи 55: запросы на новых потоках той же связи, пока она не перенесёт
 * 2 × бюджет датаграмм (сервер отвечает — не заблокировано) или сервер не
 * замолчит (PING без ответа — обрыв воспроизведён).
 *
 * Стенд на петле: связь d2k_qc с ключами из постоянного секрета (как
 * test_quicconn_fc), «сервер» в своём потоке читает запросы клиента и
 * отвечает по режиму. Проверяется d2k_quic_data_stage — тот же этап, что
 * у прямого запроса поиска. */
#include "quicconn.c"

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>

#include "d2k_quic_arms.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { printf("FAIL %s (line %d)\n", m, __LINE__); fails++; } \
                         else { printf("ok   %s\n", m); } } while (0)

enum {
    M_SHORT_THEN_SILENT, /* короткие полные ответы, всего 15 пакетов сервера, потом тишина */
    M_MANY,              /* до 200 коротких полных ответов, PING подтверждается */
    M_CUT_LATER,         /* первый ответ целиком (2 пакета), второй встаёт после HEADERS */
    M_ONE_BIG_CUT,       /* один ответ без FIN: 15 пакетов, тишина */
    M_ALIVE_NO_ANSWER    /* первый ответ целиком, дальше только подтверждает PING */
};

typedef struct {
    d2k_qc *srv;
    int mode;
    volatile int stop;
    int sent;       /* пакетов сервера всего */
    int responses;  /* ответов на запросы */
    int requests;   /* запросов клиента (потоки 4k с FIN) */
    int pings;      /* PING клиента */
} stand;

static void keys(d2k_qc *c) {
    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].tx) == 0);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].rx) == 0);
}

/* Кадр STREAM: HEADERS (:status 200, QPACK статический индекс 25) и/или
   DATA, смещение off, FIN по признаку. */
static int srv_stream(stand *st, uint64_t sid, uint64_t off, int headers, size_t data, int fin) {
    if (st->mode == M_SHORT_THEN_SILENT && st->sent >= 15) return 0;
    uint8_t body[1200];
    size_t b = 0;
    if (headers) {
        static const uint8_t h[] = {0x01, 0x03, 0x00, 0x00, 0xd9};
        memcpy(body, h, sizeof h);
        b += sizeof h;
    }
    if (data) {
        body[b++] = 0x00;
        b += d2k_qw_varint_write(body + b, sizeof body - b, data);
        memset(body + b, 'x', data);
        b += data;
    }
    uint8_t fr[1300];
    size_t o = 0;
    fr[o++] = (uint8_t)(0x08 | 0x04 | 0x02 | (fin ? 1 : 0));
    o += d2k_qw_varint_write(fr + o, sizeof fr - o, sid);
    o += d2k_qw_varint_write(fr + o, sizeof fr - o, off);
    o += d2k_qw_varint_write(fr + o, sizeof fr - o, b);
    memcpy(fr + o, body, b);
    o += b;
    char err[160];
    if (send_level(st->srv, D2K_QW_LEVEL_APP, fr, o, 0, err, sizeof err) != 0) return -1;
    st->sent++;
    return (int)b;
}

static void srv_ack(stand *st) {
    /* Молчащий сервер не отвечает и на PING. */
    if (st->mode != M_MANY && st->mode != M_ALIVE_NO_ANSWER) return;
    level *L = &st->srv->lv[D2K_QW_LEVEL_APP];
    uint8_t ab[32];
    size_t an = build_ack(ab, sizeof ab, L->largest_rx);
    char err[160];
    if (send_level(st->srv, D2K_QW_LEVEL_APP, ab, an, 0, err, sizeof err) == 0) st->sent++;
}

static void srv_request(stand *st, uint64_t sid) {
    st->requests++;
    switch (st->mode) {
    case M_SHORT_THEN_SILENT: {
        /* Три пакета на ответ: HEADERS, DATA, DATA+FIN. */
        int a = srv_stream(st, sid, 0, 1, 0, 0);
        if (a <= 0) return;
        int b = srv_stream(st, sid, (uint64_t)a, 0, 300, 0);
        if (b <= 0) return;
        if (srv_stream(st, sid, (uint64_t)(a + b), 0, 300, 1) > 0) st->responses++;
        break;
    }
    case M_MANY:
        if (st->responses < 200 && srv_stream(st, sid, 0, 1, 200, 1) > 0) st->responses++;
        break;
    case M_ALIVE_NO_ANSWER:
    case M_CUT_LATER:
        if (st->requests == 1) {
            int a = srv_stream(st, sid, 0, 1, 0, 0);
            if (a > 0 && srv_stream(st, sid, (uint64_t)a, 0, 500, 1) > 0) st->responses++;
        } else if (st->requests == 2 && st->mode == M_CUT_LATER) {
            (void)srv_stream(st, sid, 0, 1, 0, 0); /* HEADERS — и тишина */
        }
        break;
    case M_ONE_BIG_CUT:
        if (st->requests == 1) {
            uint64_t off = 0;
            for (int k = 0; k < 15; k++) {
                int n = srv_stream(st, sid, off, k == 0, 1000, 0);
                if (n <= 0) break;
                off += (uint64_t)n;
            }
        }
        break;
    }
}

/* Кадры пакета клиента: запросы (поток 4k, FIN) и PING. */
static void srv_frames(stand *st, const uint8_t *p, size_t n) {
    size_t i = 0, w = 0;
    int ping = 0;
    while (i < n) {
        uint64_t t = 0, a = 0, cnt = 0;
        if (d2k_qw_varint_read(p + i, n - i, &t, &w) != 0) return;
        i += w;
        if (t == 0x00) continue;
        if (t == 0x01) { ping = 1; st->pings++; continue; }
        if (t == 0x02 || t == 0x03) {
            for (int k = 0; k < 4; k++) {
                if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
                i += w;
                if (k == 2) cnt = a;
            }
            for (uint64_t k = 0; k < 2 * cnt; k++) {
                if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
                i += w;
            }
            if (t == 0x03) for (int k = 0; k < 3; k++) {
                if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
                i += w;
            }
            continue;
        }
        if (t == 0x10) { if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return; i += w; continue; }
        if (t == 0x11) {
            for (int k = 0; k < 2; k++) {
                if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
                i += w;
            }
            continue;
        }
        if (t >= 0x08 && t <= 0x0f) {
            uint64_t sid = 0, off = 0, len = 0;
            if (d2k_qw_varint_read(p + i, n - i, &sid, &w)) return;
            i += w;
            if (t & 0x04) { if (d2k_qw_varint_read(p + i, n - i, &off, &w)) return; i += w; }
            if (t & 0x02) { if (d2k_qw_varint_read(p + i, n - i, &len, &w)) return; i += w; }
            else len = n - i;
            if (len > n - i) return;
            i += (size_t)len;
            /* Повтор запроса (PTO клиента) — тот же поток: отвечаем один раз. */
            if ((sid & 0x03) == 0 && (t & 0x01) && sid / 4 + 1 > (uint64_t)st->requests)
                srv_request(st, sid);
            continue;
        }
        return;
    }
    if (ping) srv_ack(st);
}

static void *srv_run(void *arg) {
    stand *st = arg;
    level *L = &st->srv->lv[D2K_QW_LEVEL_APP];
    while (!st->stop) {
        uint8_t pk[DGRAM_IN];
        ssize_t n = recv(st->srv->fd, pk, sizeof pk, 0);
        if (n <= 0) continue;
        d2k_qw_hdr h;
        if (d2k_qw_hdr_parse(pk, (size_t)n, 8, &h) != 0 || h.long_hdr) continue;
        uint8_t plain[DGRAM_IN];
        size_t plen = 0;
        uint64_t pn = 0;
        if (d2k_qw_open(&L->rx, &h, pk, L->have_rx ? L->largest_rx : 0, plain, &plen, &pn) != 0)
            continue;
        if (!L->have_rx || pn > L->largest_rx) L->largest_rx = pn;
        L->have_rx = 1;
        srv_frames(st, plain, plen);
    }
    return NULL;
}

static d2k_quic_arm_data run(int mode, unsigned budget_pk, stand *out) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    assert(getsockname(s, (struct sockaddr *)&a, &len) == 0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0);
    struct sockaddr_in ca;
    socklen_t cl = sizeof ca;
    assert(getsockname(fd, (struct sockaddr *)&ca, &cl) == 0);
    assert(connect(s, (struct sockaddr *)&ca, cl) == 0);
    struct timeval tv = {0, 50000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    d2k_qc *c = calloc(1, sizeof *c);
    d2k_qc *srv = calloc(1, sizeof *srv);
    assert(c && srv);
    c->fd = fd; c->peer_name = -1; c->version = D2K_QW_V1;
    c->dcid_len = 8; memset(c->dcid, 0x5a, 8);
    c->scid_len = 8; memset(c->scid, 0x77, 8);
    srv->fd = s; srv->version = D2K_QW_V1;
    srv->dcid_len = 8; memset(srv->dcid, 0x77, 8);
    keys(c); keys(srv);

    stand st;
    memset(&st, 0, sizeof st);
    st.srv = srv;
    st.mode = mode;
    pthread_t th;
    assert(pthread_create(&th, NULL, srv_run, &st) == 0);

    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d2k_quic_data_stage(c, "repro.example", "/", 1, budget_pk, 300, &d);
    st.stop = 1;
    pthread_join(th, NULL);
    d2k_qc_close(c);
    close(s);
    free(srv);
    if (out) *out = st;
    printf("     режим %d: %s (сервер: %d пакетов, %d ответов, %d запросов, %d PING)\n",
           mode, d.reason, st.sent, st.responses, st.requests, st.pings);
    return d;
}

int main(void) {
    stand st;
    d2k_quic_arm_data d;

    /* Поле 04.10: короткие полные ответы, но после 15 пакетов сервер молчит.
       Один запрос «/» кончался целиком внутри бюджета — «не воспроизвёлся». */
    d = run(M_SHORT_THEN_SILENT, 25, &st);
    CHECK(d.verdict == D2K_QAD_CUT,
          "15 пакетов сервера и тишина: обрыв воспроизведён, хотя первый ответ пришёл целиком");
    CHECK(st.requests >= 2, "после полного короткого ответа ушёл следующий запрос на новом потоке");
    /* «Сервер молчит» доказывается PING: он обязан дойти до сервера.
       Прежде пакет из одного PING не запечатывался (номер 1 байт + тело
       1 байт короче образца защиты заголовка, RFC 9001 §5.4.2) и молча не
       уходил — «два PING без ответа» было просто тишиной. */
    CHECK(st.pings >= 2, "PING тишины дошёл до сервера");

    /* Сервер отвечает на каждый запрос: связь переносит 2 × бюджет — не заблокировано. */
    d = run(M_MANY, 25, &st);
    CHECK(d.verdict == D2K_QAD_PASS, "сервер отвечает на каждый запрос: бюджет пройден, не обрыв");
    CHECK(st.requests >= 2 && st.responses < 200,
          "бюджет пройден повторами, без лишних запросов сверх 2 × бюджет");

    /* Первый запрос целиком, второй встаёт: прежде — «приходит целиком». */
    d = run(M_CUT_LATER, 25, &st);
    CHECK(d.verdict == D2K_QAD_CUT, "первый ответ целиком, второй встал: обрыв воспроизведён");
    CHECK(st.requests == 2, "второй запрос ушёл новым потоком той же связи");

    /* Один большой ответ без FIN, тишина: обрыв и прежде, и теперь. */
    d = run(M_ONE_BIG_CUT, 25, &st);
    CHECK(d.verdict == D2K_QAD_CUT, "большой ответ встал на 15 пакетах: обрыв");
    CHECK(st.pings >= 2, "PING тишины дошёл до сервера (один большой ответ)");

    /* Сервер жив (подтверждает PING), но на второй запрос не отвечает —
       это не обрыв: «не измерено». Отличает обрыв от медленного сервера
       именно PING, дошедший до провода. */
    d = run(M_ALIVE_NO_ANSWER, 25, &st);
    CHECK(d.verdict == D2K_QAD_NOT_RUN && st.pings >= 1,
          "сервер жив и подтверждает PING, ответа нет: не обрыв, не измерено");

    /* Без бюджета (плечи) — прежнее правило: один полный ответ засчитан. */
    d = run(M_CUT_LATER, 0, &st);
    CHECK(d.verdict == D2K_QAD_PASS && st.requests == 1,
          "без бюджета (этап данных плеча) один полный ответ засчитывается, как прежде");

    if (!fails) puts("test_quic_repro_budget: all passed");
    return fails != 0;
}
