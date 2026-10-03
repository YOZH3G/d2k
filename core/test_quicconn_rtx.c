/* test_quicconn_rtx.c — повтор прикладной посылки переживает короткие чтения.
 *
 * Задача 42 (основание — задача 33): проверка читает ответ кусками по 200 мс,
 * а таймер повтора (300 мс) заводился заново в каждом вызове
 * d2k_qc_stream_recv. Срок не наступал никогда, и запрос HTTP/3 ни разу не
 * переотправлялся (подтверждено трассой). Состояние таймера обязано жить в
 * соединении. Соединение собирается прямо здесь, на петле, с ключами из
 * постоянного секрета: проверяется счёт датаграмм, а не разбор у сервера. */
#include "quicconn.c"

#include <assert.h>
#include <fcntl.h>

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "quicconn_rtx: %s\n", m); fails++; } } while (0)

static size_t drain(int fd) {
    uint8_t b[2048];
    size_t n = 0;
    while (recv(fd, b, sizeof b, 0) > 0) { n++; }
    return n;
}

static d2k_qc *app_conn(int *server) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    assert(getsockname(s, (struct sockaddr *)&a, &len) == 0);
    assert(fcntl(s, F_SETFL, O_NONBLOCK) == 0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof a) == 0);
    d2k_qc *c = calloc(1, sizeof *c);
    assert(c);
    c->fd = fd;
    c->peer_name = -1;
    c->version = D2K_QW_V1;
    c->dcid_len = 8;
    memset(c->dcid, 0x5a, c->dcid_len);
    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].tx) == 0);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].rx) == 0);
    *server = s;
    return c;
}

int main(void) {
    char err[200];
    uint8_t buf[256];
    uint64_t sid = 0;
    static const uint8_t req[] = {0x01, 0x02, 0x03};

    /* Чтение кусками по 200 мс, как в verify.c: за 1,2 с запрос обязан уйти
       повторно (сроки 300 и 900 мс от отправки). */
    int server = -1;
    d2k_qc *c = app_conn(&server);
    CHECK(d2k_qc_stream_send(c, 0, req, sizeof req, 1, err, sizeof err) == 0, "request sent");
    for (int i = 0; i < 6; i++) {
        CHECK(d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 200, err, sizeof err) == 0,
              "silent server: nothing to read");
    }
    size_t sliced = drain(server);
    CHECK(sliced >= 3, "200 ms read slices must not reset the request retransmit timer");
    d2k_qc_close(c);
    close(server);

    /* Одно длинное чтение — прежнее поведение сохраняется. */
    c = app_conn(&server);
    CHECK(d2k_qc_stream_send(c, 0, req, sizeof req, 1, err, sizeof err) == 0, "request sent");
    (void)d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 1200, err, sizeof err);
    size_t whole = drain(server);
    CHECK(whole >= 3 && whole <= 4, "one long read retransmits on the same schedule");

    /* Повторов не больше трёх на посылку, сколько ни читай. */
    for (int i = 0; i < 25; i++) {
        (void)d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 200, err, sizeof err);
    }
    CHECK(whole + drain(server) <= 4, "at most three retransmits of one request");
    d2k_qc_close(c);
    close(server);

    /* Финальное ревью core, M7 (RFC 9000 §17.2.5.2): второй или
       недействительный Retry клиент ОТБРАСЫВАЕТ, а не рвёт соединение.
       Наш DCID виден на пути, и поздний поддельный Retry иначе обрывал
       проверку раньше срока. */
    for (int mode = 0; mode < 4; mode++) {
        c = app_conn(&server);
        c->scid_len = 8; memset(c->scid, 0x11, 8);
        c->odcid_len = 8; memset(c->odcid, 0x22, 8);
        memcpy(c->dcid, c->odcid, 8); c->dcid_len = 8;
        if (mode == 1) c->retry_count = 1;       /* Retry уже был */
        if (mode == 3) c->peer_cid_fixed = 1;    /* сервер уже ответил пакетом */
        static const uint8_t rscid[8] = {9, 9, 9, 9, 9, 9, 9, 9};
        uint8_t rb[256];
        size_t rl = d2k_qw_retry_build(rb, sizeof rb, D2K_QW_V1, c->odcid, 8,
                                       c->scid, 8, rscid, sizeof rscid,
                                       (const uint8_t *)"tok", 3);
        CHECK(rl > 0, "retry fixture");
        if (mode == 2) rb[rl - 1] ^= 1;          /* испорченный тег */
        struct sockaddr_in ca; socklen_t cl = sizeof ca;
        assert(getsockname(c->fd, (struct sockaddr *)&ca, &cl) == 0);
        CHECK(sendto(server, rb, rl, 0, (struct sockaddr *)&ca, cl) == (ssize_t)rl, "retry sent");
        int r = recv_dgram(c, 500, err, sizeof err);
        if (mode == 0) {
            CHECK(r == 2 && c->retry_pending == 1, "first valid Retry is taken");
        } else {
            CHECK(r == 0, "second/invalid/late Retry is discarded, not a connection failure");
            CHECK(c->retry_pending == 0 && c->dcid[0] == 0x22,
                  "discarded Retry changes nothing in the connection");
        }
        d2k_qc_close(c);
        close(server);
    }

    if (!fails) { puts("QUIC: request retransmit timer survives sliced reads"); }
    return fails != 0;
}
