/* http80.c — вставка провайдера в открытый HTTP (задача 51), см. d2k_http80.h.
 *
 * Только первые пакеты потоков порта 80; таблица фиксированного размера,
 * вытеснение самого давнего. Решение принимается на первом пакете сервера с
 * нагрузкой после запроса — дальше поток модулю неинтересен.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "d2k_http80.h"
#include "d2k_httpup.h"
#include "d2k_packet.h"

enum {
    ST_FREE = 0,
    ST_SYN,        /* видели SYN клиента */
    ST_OPEN,       /* видели SYN/ACK: RTT замерен, ISN сервера известен */
    ST_REQUEST,    /* видели запрос GET/HEAD целиком */
    ST_INJECTED,   /* вставка узнана и пропущена как есть */
    ST_ANSWERED,   /* вместо вставки ушёл 307: сервер по потоку снимается */
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

typedef struct {
    char name[254];
    uint64_t expires;
} https_name;

struct d2k_http80 {
    flow flows[D2K_HTTP80_FLOWS];
    https_name names[D2K_HTTP80_NAMES];
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

/* --- имена с подтверждённым HTTPS --------------------------------------- */

static size_t name_norm(const char *name, size_t len, char *o, size_t cap) {
    if (!name) { return 0; }
    if (len && name[len - 1] == '.') { len--; }
    if (len == 0 || len >= cap) { return 0; }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.')) { return 0; }
        o[i] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
    o[len] = '\0';
    return len;
}

int d2k_http80_set_https(d2k_http80 *h, const char *name, size_t len, uint64_t expires) {
    char n[254];
    if (!h || !name_norm(name, len, n, sizeof n)) { return -1; }
    https_name *pick = NULL;
    for (size_t i = 0; i < D2K_HTTP80_NAMES; i++) {
        if (h->names[i].name[0] && strcmp(h->names[i].name, n) == 0) { pick = &h->names[i]; break; }
    }
    if (expires == 0) {
        if (pick) { memset(pick, 0, sizeof *pick); }
        return 0;
    }
    if (!pick) {
        for (size_t i = 0; i < D2K_HTTP80_NAMES; i++) {
            https_name *e = &h->names[i];
            if (!e->name[0]) { pick = e; break; }
            if (!pick || e->expires < pick->expires) { pick = e; }
        }
        memcpy(pick->name, n, sizeof pick->name);
    }
    pick->expires = expires;
    return 0;
}

int d2k_http80_https(const d2k_http80 *h, const char *host, uint64_t now) {
    char n[254];
    if (!h || !host || !name_norm(host, strlen(host), n, sizeof n)) { return 0; }
    for (size_t i = 0; i < D2K_HTTP80_NAMES; i++) {
        if (h->names[i].name[0] && strcmp(h->names[i].name, n) == 0) {
            return now < h->names[i].expires;
        }
    }
    return 0;
}

/* --- сборка пакетов ------------------------------------------------------- */

static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static uint32_t sum16(const uint8_t *p, size_t n, uint32_t acc) {
    for (; n > 1; p += 2, n -= 2) { acc += (uint32_t)p[0] << 8 | p[1]; }
    if (n) { acc += (uint32_t)p[0] << 8; }
    return acc;
}

static uint16_t fold(uint32_t acc) {
    while (acc >> 16) { acc = (acc & 0xffffu) + (acc >> 16); }
    return (uint16_t)~acc;
}

/* IP + TCP без опций. Адреса — из потока, поля IP (TOS/TTL/метка потока) —
   из пакета, который заменяем; у RST — обычные 64. */
static size_t build(uint8_t family, const uint8_t *src, const uint8_t *dst,
                    uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                    uint8_t flags, uint16_t window, uint8_t ttl, uint8_t tclass,
                    uint32_t flow_label, uint16_t ip_id,
                    const char *pay, size_t plen, uint8_t *o, size_t cap) {
    size_t ip = family == 6 ? 40 : 20, n = ip + 20 + plen;
    if (!o || n > cap || n > 0xffff) { return 0; }
    memset(o, 0, ip + 20);
    uint32_t acc;
    if (family == 6) {
        o[0] = (uint8_t)(0x60 | tclass >> 4);
        o[1] = (uint8_t)((tclass & 15u) << 4 | ((flow_label >> 16) & 15u));
        wr16(o + 2, flow_label & 0xffffu);
        wr16(o + 4, (unsigned)(20 + plen));
        o[6] = 6; o[7] = ttl;
        memcpy(o + 8, src, 16); memcpy(o + 24, dst, 16);
        acc = sum16(o + 8, 32, (uint32_t)(20 + plen) + 6);
    } else {
        o[0] = 0x45; o[1] = tclass;
        wr16(o + 2, (unsigned)n); wr16(o + 4, ip_id); wr16(o + 6, 0x4000);
        o[8] = ttl; o[9] = 6;
        memcpy(o + 12, src, 4); memcpy(o + 16, dst, 4);
        wr16(o + 10, fold(sum16(o, 20, 0)));
        acc = sum16(o + 12, 8, (uint32_t)(20 + plen) + 6);
    }
    uint8_t *t = o + ip;
    wr16(t, sport); wr16(t + 2, dport);
    wr32(t + 4, seq); wr32(t + 8, ack);
    t[12] = 0x50; t[13] = flags; wr16(t + 14, window);
    if (plen) { memcpy(t + 20, pay, plen); }
    wr16(t + 16, fold(sum16(t, 20 + plen, acc)));
    return n;
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
                       uint8_t *out, size_t out_cap, uint8_t *rst, size_t rst_cap,
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
    if (f->state == ST_ANSWERED) {
        /* Клиент уже получил 307 и FIN: копия вставки, её FIN и поздний
           настоящий ответ ему только навредят. */
        r->action = D2K_HTTP80_DROP;
        h->st.dropped++;
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

    if (!d2k_http80_https(h, f->host, now)) { return; }
    char redirect[D2K_HTTP80_TARGET_MAX + 512];
    size_t rl = d2k_httpup_redirect_https(f->host, f->target, redirect, sizeof redirect);
    uint16_t window = (uint16_t)((unsigned)t[14] << 8 | t[15]);
    size_t n = rl ? build(v.family, f->server, f->client, 80, f->cport, f->server_next,
                          f->client_next, 0x19 /* FIN|PSH|ACK */, window, v.hop_limit,
                          v.traffic_class, v.flow_label, v.ip_id, redirect, rl, out, out_cap)
                  : 0;
    size_t m = n ? build(v.family, f->client, f->server, f->cport, 80, f->client_next,
                         f->server_next, 0x14 /* RST|ACK */, 0, 64, 0, 0, 0,
                         NULL, 0, rst, rst_cap)
                 : 0;
    if (!n || !m) { return; }   /* не собралось — вставка проходит как есть */
    f->state = ST_ANSWERED;
    h->st.answered++;
    r->answered = 1;
    r->action = D2K_HTTP80_REPLACE;
    r->len = n;
    r->rst_len = m;
}
