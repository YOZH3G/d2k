/* test_quicconn_fc.c — наш клиент QUIC обязан быть честным приёмником
 * (задача 50, раунд 4, N1).
 *
 * d2k_qc объявляет окно потока 256 КБ и соединения 1 МБ и прежде не
 * расширял их никогда: сервер останавливался на 256 КБ и ждал, ответ не
 * завершался, и правило «засчитывается только ответ целиком» делало любой
 * больший ресурс вечным «не измерено» — обход большого ресурса никогда не
 * засчитывался, а запрет QUIC продлевался бесконечно. Теперь клиент шлёт
 * MAX_STREAM_DATA / MAX_DATA, когда принята половина окна (RFC 9000 §4.2).
 *
 * Стенд на петле: «сервер» шлёт поток 1 МБ ровно в пределах выданного ему
 * кредита и читает из пакетов клиента кадры MAX_STREAM_DATA и MAX_DATA. */
#include "quicconn.c"

#include <assert.h>
#include <fcntl.h>

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "quicconn_fc: %s\n", m); fails++; } } while (0)

static void keys(d2k_qc *c) {
    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].tx) == 0);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].rx) == 0);
}

/* Кадры кредита в пакете клиента. */
static void scan_credit(const uint8_t *p, size_t n, uint64_t *stream_lim, uint64_t *conn_lim) {
    size_t i = 0, w = 0;
    while (i < n) {
        uint64_t t = 0;
        if (d2k_qw_varint_read(p + i, n - i, &t, &w) != 0) return;
        i += w;
        uint64_t a = 0, b = 0, cnt = 0;
        switch (t) {
        case 0x00: case 0x01: break;
        case 0x02: case 0x03:
            for (int k = 0; k < 4; k++) { if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return; i += w;
                if (k == 2) cnt = a; }
            for (uint64_t k = 0; k < 2 * cnt; k++) { if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return; i += w; }
            if (t == 0x03) for (int k = 0; k < 3; k++) { if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return; i += w; }
            break;
        case 0x10:
            if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
            i += w;
            if (a > *conn_lim) *conn_lim = a;
            break;
        case 0x11:
            if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
            i += w;
            if (d2k_qw_varint_read(p + i, n - i, &b, &w)) return;
            i += w;
            if (a == 0 && b > *stream_lim) *stream_lim = b;
            break;
        default:
            if (t >= 0x08 && t <= 0x0f) {
                uint64_t off = 0, len = 0;
                if (d2k_qw_varint_read(p + i, n - i, &a, &w)) return;
                i += w;
                if (t & 4) { if (d2k_qw_varint_read(p + i, n - i, &off, &w)) return; i += w; }
                if (t & 2) { if (d2k_qw_varint_read(p + i, n - i, &len, &w)) return; i += w; }
                else len = n - i;
                i += (size_t)len;
                break;
            }
            return;
        }
    }
}

int main(void) {
    char err[200];
    uint8_t buf[4096];
    uint64_t sid = 0;
    /* Сокеты на петле. */
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
    int big = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    struct sockaddr_in ca;
    socklen_t cl = sizeof ca;
    assert(getsockname(fd, (struct sockaddr *)&ca, &cl) == 0);
    assert(connect(s, (struct sockaddr *)&ca, cl) == 0);
    assert(fcntl(s, F_SETFL, O_NONBLOCK) == 0);

    d2k_qc *c = calloc(1, sizeof *c);
    d2k_qc *srv = calloc(1, sizeof *srv);
    assert(c && srv);
    c->fd = fd; c->peer_name = -1; c->version = D2K_QW_V1;
    c->dcid_len = 8; memset(c->dcid, 0x5a, 8);       /* наш адрес серверу */
    c->scid_len = 8; memset(c->scid, 0x77, 8);       /* адрес клиента */
    srv->fd = s; srv->version = D2K_QW_V1;
    srv->dcid_len = 8; memset(srv->dcid, 0x77, 8);
    keys(c); keys(srv);

    static const uint8_t req[] = {0x01, 0x02, 0x03};
    CHECK(d2k_qc_stream_send(c, 0, req, sizeof req, 1, err, sizeof err) == 0, "request sent");

    const uint64_t total = 1048576;
    uint64_t sent = 0, stream_lim = 262144, conn_lim = 1048576;
    uint64_t max_stuck = 0;
    for (int iter = 0; iter < 4000 && sent < total; iter++) {
        /* Сервер: пачка кадров в пределах кредита. */
        uint64_t lim = stream_lim < conn_lim ? stream_lim : conn_lim;
        for (int k = 0; k < 24 && sent < total && sent < lim; k++) {
            uint64_t l = 1000;
            if (l > total - sent) l = total - sent;
            if (l > lim - sent) l = lim - sent;
            uint8_t fr[1200];
            size_t o = 0;
            int fin = sent + l == total;
            fr[o++] = (uint8_t)(0x08 | 0x04 | 0x02 | (fin ? 1 : 0));
            o += d2k_qw_varint_write(fr + o, sizeof fr - o, 0);
            o += d2k_qw_varint_write(fr + o, sizeof fr - o, sent);
            o += d2k_qw_varint_write(fr + o, sizeof fr - o, l);
            memset(fr + o, 'x', (size_t)l);
            o += (size_t)l;
            CHECK(send_level(srv, D2K_QW_LEVEL_APP, fr, o, 0, err, sizeof err) == 0, "server send");
            sent += l;
        }
        if (sent >= lim && sent < total) max_stuck++;
        /* Клиент читает всё, что пришло. */
        for (int k = 0; k < 200; k++) {
            long r = d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 2, err, sizeof err);
            if (r == 0) break;
            CHECK(r > 0, "client read");
            if (r < 0) break;
        }
        /* Сервер: кредит из пакетов клиента. */
        uint8_t pk[DGRAM_IN];
        ssize_t n;
        while ((n = recv(s, pk, sizeof pk, 0)) > 0) {
            d2k_qw_hdr h;
            if (d2k_qw_hdr_parse(pk, (size_t)n, 8, &h) != 0 || h.long_hdr) continue;
            uint8_t plain[DGRAM_IN];
            size_t plen = 0;
            uint64_t pn = 0;
            level *L = &srv->lv[D2K_QW_LEVEL_APP];
            if (d2k_qw_open(&L->rx, &h, pk, L->have_rx ? L->largest_rx : 0, plain, &plen, &pn) != 0) continue;
            if (!L->have_rx || pn > L->largest_rx) L->largest_rx = pn;
            L->have_rx = 1;
            scan_credit(plain, plen, &stream_lim, &conn_lim);
        }
        if (max_stuck > 200) break;
    }
    /* Добрать хвост. */
    for (int k = 0; k < 400; k++) {
        if (d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 2, err, sizeof err) <= 0) break;
    }
    uint64_t got = 0;
    int complete = 0;
    d2k_qc_app_progress(c, &got, &complete);
    CHECK(sent == total, "сервер упёрся в окно 256 КБ: клиент не расширяет кредит");
    CHECK(complete && got == total, "ответ 1 МБ не завершился при честном кредите");
    CHECK(stream_lim > 262144 && conn_lim > 1048576 - 1, "MAX_STREAM_DATA не приходили");
    d2k_qc_close(c);
    free(srv);
    close(s);
    if (!fails) puts("QUIC: окно расширяется, ответ 1 МБ приходит целиком");
    return fails != 0;
}
