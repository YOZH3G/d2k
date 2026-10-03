/* http80.c — вставка провайдера в открытый HTTP (задача 51), см. d2k_http80.h.
 *
 * Только первые пакеты потоков порта 80; таблица фиксированного размера,
 * вытеснение самого давнего. Решение принимается на первом пакете сервера с
 * нагрузкой после запроса — дальше поток модулю неинтересен.
 */
#include <stdlib.h>
#include <string.h>

#include "d2k_http80.h"
#include "d2k_httpup.h"
#include "d2k_packet.h"

enum {
    ST_FREE = 0,
    ST_SYN,        /* видели SYN клиента */
    ST_OPEN,       /* видели SYN/ACK: RTT замерен, ISN сервера известен */
    ST_REQUEST,    /* видели запрос GET/HEAD целиком */
    ST_INJECTED,   /* вставка узнана и пропущена как есть */
    ST_DONE        /* решать больше нечего */
};

typedef struct {
    uint8_t state, family;
    uint8_t client[16], server[16];
    uint16_t cport, sport;
    uint64_t t_syn, t_req, touched, rtt;
    uint32_t server_next, client_next;
    char host[256];
    char target[D2K_HTTP80_TARGET_MAX];
} flow;

struct d2k_http80 {
    flow flows[D2K_HTTP80_FLOWS];
    d2k_http80_stats st;
};

d2k_http80 *d2k_http80_new(void) {
    return calloc(1, sizeof(d2k_http80));
}

void d2k_http80_free(d2k_http80 *h) {
    free(h);
}

d2k_http80_stats d2k_http80_get_stats(const d2k_http80 *h) {
    d2k_http80_stats z;
    memset(&z, 0, sizeof z);
    return h ? h->st : z;
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Монотонные часы, но пакет из одной пачки может прийти с отметкой раньше
   соседнего: разность в обратную сторону — не «давно». */
static int stale(const flow *f, uint64_t now) {
    return now > f->touched && now - f->touched > D2K_HTTP80_IDLE_NS;
}

static flow *find(d2k_http80 *h, uint8_t family, const uint8_t *client, uint16_t cport,
                  const uint8_t *server, uint16_t sport, uint64_t now) {
    size_t alen = family == 6 ? 16 : 4;
    for (size_t i = 0; i < D2K_HTTP80_FLOWS; i++) {
        flow *f = &h->flows[i];
        if (f->state == ST_FREE || f->family != family || f->cport != cport ||
            f->sport != sport || memcmp(f->client, client, alen) != 0 ||
            memcmp(f->server, server, alen) != 0) { continue; }
        if (stale(f, now)) {
            f->state = ST_FREE;
            return NULL;
        }
        return f;
    }
    return NULL;
}

static flow *make(d2k_http80 *h, uint8_t family, const uint8_t *client, uint16_t cport,
                  const uint8_t *server, uint16_t sport, uint64_t now) {
    flow *pick = NULL;
    for (size_t i = 0; i < D2K_HTTP80_FLOWS; i++) {
        flow *f = &h->flows[i];
        if (f->state == ST_FREE || stale(f, now)) { pick = f; break; }
        if (!pick || f->touched < pick->touched) { pick = f; }
    }
    if (pick->state != ST_FREE && !stale(pick, now)) {
        h->st.evicted++;
    }
    memset(pick, 0, sizeof *pick);
    pick->family = family;
    memcpy(pick->client, client, family == 6 ? 16 : 4);
    memcpy(pick->server, server, family == 6 ? 16 : 4);
    pick->cport = cport;
    pick->sport = sport;
    pick->touched = now;
    return pick;
}

void d2k_http80_packet(d2k_http80 *h, const uint8_t *pkt, size_t len, uint64_t now,
                       d2k_http80_res *r) {
    if (!r) { return; }
    memset(r, 0, sizeof *r);
    r->action = D2K_HTTP80_PASS;
    d2k_packet_view v;
    if (!h || !d2k_packet_parse(pkt, len, &v) || v.protocol != 6) { return; }
    const uint8_t *t = pkt + v.l4;
    size_t thl = (size_t)(t[12] >> 4) * 4u;
    if (thl < 20 || thl > v.total - v.l4) { return; }
    unsigned sport = (unsigned)t[0] << 8 | t[1], dport = (unsigned)t[2] << 8 | t[3];
    int to_server;
    if (dport == 80 && sport != 80) { to_server = 1; }
    else if (sport == 80 && dport != 80) { to_server = 0; }
    else { return; }

    const uint8_t *client = to_server ? v.src.bytes : v.dst.bytes;
    const uint8_t *server = to_server ? v.dst.bytes : v.src.bytes;
    uint16_t cport = (uint16_t)(to_server ? sport : dport);
    uint8_t flags = t[13];
    uint32_t seq = rd32(t + 4), ack = rd32(t + 8);
    const uint8_t *pay = t + thl;
    size_t plen = v.total - v.l4 - thl;

    flow *f = find(h, v.family, client, cport, server, 80, now);

    if (to_server) {
        if ((flags & 0x12) == 0x02) {          /* SYN без ACK: новый поток */
            if (!f) { f = make(h, v.family, client, cport, server, 80, now); }
            else { memset(f->host, 0, sizeof f->host); }
            f->state = ST_SYN;
            f->t_syn = now;
            f->touched = now;
            return;
        }
        if (!f) { return; }
        f->touched = now;
        if (f->state == ST_OPEN && plen > 0) {
            /* Первая нагрузка клиента — запрос целиком в одном пакете, ровно
               с начала потока. Кусок запроса не разобрать: решать не по чему. */
            if (seq == f->client_next &&
                d2k_httpup_request_target((const char *)pay, plen, f->host, sizeof f->host,
                                          f->target, sizeof f->target)) {
                f->state = ST_REQUEST;
                f->t_req = now;
                f->client_next = seq + (uint32_t)plen;
                h->st.requests++;
            } else {
                f->state = ST_DONE;
            }
        }
        return;
    }

    if (!f) { return; }
    f->touched = now;
    if ((flags & 0x12) == 0x12) {              /* SYN/ACK */
        if (f->state == ST_SYN && now >= f->t_syn) {
            f->rtt = now - f->t_syn;
            f->server_next = seq + 1;
            f->client_next = ack;
            f->state = ST_OPEN;
        }
        return;
    }
    if (plen == 0 || f->state != ST_REQUEST) { return; }

    /* Первый ответ сервера с нагрузкой: решение принимается здесь и один раз. */
    f->state = ST_DONE;
    uint64_t dt = now >= f->t_req ? now - f->t_req : 0;
    if (seq != f->server_next || ack != f->client_next || f->rtt == 0 || dt * 2 >= f->rtt ||
        !d2k_httpup_portal_location(f->host, (const char *)pay, plen,
                                    r->portal, sizeof r->portal)) {
        r->portal[0] = '\0';
        return;
    }
    f->state = ST_INJECTED;
    h->st.injections++;
    r->injection = 1;
    r->family = v.family;
    memcpy(r->client, f->client, sizeof r->client);
    memcpy(r->server, f->server, sizeof r->server);
    r->client_port = f->cport;
    r->server_port = f->sport;
    r->rtt_ns = f->rtt;
    r->reply_ns = dt;
    memcpy(r->host, f->host, sizeof r->host);
}
