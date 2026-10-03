/* ctq.c — контракт и обоснования в d2k_ctq.h. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "d2k_ctq.h"
#include "d2k_nl.h"

static size_t align4(size_t n) { return (n + 3u) & ~(size_t)3u; }

static void wr16h(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void wr32h(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint16_t rd16h(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint64_t rd64be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static uint32_t rd32be(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Атрибут с полезной нагрузкой; возвращает новую позицию или 0. */
static size_t put(uint8_t *o, size_t cap, size_t pos, uint16_t type,
                  const void *val, size_t vlen) {
    size_t alen = D2K_NLA_HDRLEN + vlen, step = align4(alen);
    if (pos + step > cap) return 0;
    wr16h(o + pos, (uint16_t)alen);
    wr16h(o + pos + 2, type);
    if (vlen) memcpy(o + pos + 4, val, vlen);
    memset(o + pos + alen, 0, step - alen);
    return pos + step;
}

/* Открыть вложенный атрибут: заголовок пишется, длина — при закрытии. */
static size_t open_nest(uint8_t *o, size_t cap, size_t pos, uint16_t type) {
    if (pos + D2K_NLA_HDRLEN > cap) return 0;
    wr16h(o + pos + 2, (uint16_t)(type | D2K_NLA_F_NESTED));
    return pos + D2K_NLA_HDRLEN;
}
static void close_nest(uint8_t *o, size_t start, size_t end) {
    wr16h(o + start, (uint16_t)(end - start));
}

size_t d2k_ct_get_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t) {
    if (!o || !t || (t->family != 4 && t->family != 6) || cap < 20) return 0;
    size_t alen = t->family == 6 ? 16 : 4;
    size_t pos = D2K_NLMSG_HDRLEN;
    o[pos++] = t->family == 6 ? 10 : 2;   /* AF_INET6 / AF_INET (Linux) */
    o[pos++] = D2K_NFNETLINK_V0;
    o[pos++] = 0; o[pos++] = 0;           /* res_id */
    size_t tup = pos;
    if (!(pos = open_nest(o, cap, pos, D2K_CTA_TUPLE_ORIG))) return 0;
    size_t ipn = pos;
    if (!(pos = open_nest(o, cap, pos, D2K_CTA_TUPLE_IP))) return 0;
    if (!(pos = put(o, cap, pos, t->family == 6 ? D2K_CTA_IP_V6_SRC : D2K_CTA_IP_V4_SRC,
                    t->src, alen))) return 0;
    if (!(pos = put(o, cap, pos, t->family == 6 ? D2K_CTA_IP_V6_DST : D2K_CTA_IP_V4_DST,
                    t->dst, alen))) return 0;
    close_nest(o, ipn, pos);
    size_t prn = pos;
    if (!(pos = open_nest(o, cap, pos, D2K_CTA_TUPLE_PROTO))) return 0;
    if (!(pos = put(o, cap, pos, D2K_CTA_PROTO_NUM, &t->proto, 1))) return 0;
    if (!(pos = put(o, cap, pos, D2K_CTA_PROTO_SRC_PORT, t->sport_be, 2))) return 0;
    if (!(pos = put(o, cap, pos, D2K_CTA_PROTO_DST_PORT, t->dport_be, 2))) return 0;
    close_nest(o, prn, pos);
    close_nest(o, tup, pos);
    wr32h(o, (uint32_t)pos);
    wr16h(o + 4, (uint16_t)(D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_GET));
    wr16h(o + 6, D2K_NLM_F_REQUEST);
    wr32h(o + 8, seq);
    wr32h(o + 12, 0);
    return pos;
}

/* Счётчик пакетов из вложенного CTA_COUNTERS_*: 0 — найден. */
static int counter(const uint8_t *p, size_t n, uint64_t *out) {
    size_t off = 0;
    while (off + D2K_NLA_HDRLEN <= n) {
        uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
        if (alen < D2K_NLA_HDRLEN || alen > n - off) return -1;
        const uint8_t *v = p + off + D2K_NLA_HDRLEN;
        size_t vl = alen - D2K_NLA_HDRLEN;
        if (type == D2K_CTA_COUNTERS_PACKETS && vl == 8) { *out = rd64be(v); return 0; }
        if (type == D2K_CTA_COUNTERS32_PACKETS && vl == 4) { *out = rd32be(v); return 0; }
        off += align4(alen);
    }
    return -1;
}

int d2k_ct_counters_parse(const uint8_t *buf, size_t len, uint32_t seq,
                          uint64_t *orig_pkts, uint64_t *reply_pkts) {
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    while (d2k_nl_next(&it, &m)) {
        if (m.seq != seq) continue;
        int32_t e = 0;
        if (d2k_nl_errno(&m, &e) == 0) return e == 0 ? -1 : 1;
        if (m.type != (D2K_NFNL_SUBSYS_CTNETLINK << 8 | D2K_IPCTNL_MSG_CT_NEW) ||
            m.body_len < D2K_NFGENMSG_LEN) return -1;
        const uint8_t *p = m.body + D2K_NFGENMSG_LEN;
        size_t n = m.body_len - D2K_NFGENMSG_LEN, off = 0;
        int have_o = 0, have_r = 0;
        uint64_t o = 0, r = 0;
        while (off + D2K_NLA_HDRLEN <= n) {
            uint16_t alen = rd16h(p + off), type = rd16h(p + off + 2) & D2K_NLA_TYPE_MASK;
            if (alen < D2K_NLA_HDRLEN || alen > n - off) return -1;
            const uint8_t *v = p + off + D2K_NLA_HDRLEN;
            size_t vl = alen - D2K_NLA_HDRLEN;
            if (type == D2K_CTA_COUNTERS_ORIG) have_o = counter(v, vl, &o) == 0;
            if (type == D2K_CTA_COUNTERS_REPLY) have_r = counter(v, vl, &r) == 0;
            off += align4(alen);
        }
        if (!have_o || !have_r) return -1;
        if (orig_pkts) *orig_pkts = o;
        if (reply_pkts) *reply_pkts = r;
        return 0;
    }
    return -1;
}

int d2k_ct_query_fd(int fd, uint32_t seq, const d2k_ct_tuple *t,
                    uint64_t *orig_pkts, uint64_t *reply_pkts) {
    if (fd < 0 || !t) return -1;
    uint8_t req[128];
    size_t n = d2k_ct_get_req(req, sizeof req, seq, t);
    if (!n) return -1;
    if (send(fd, req, n, MSG_DONTWAIT) != (ssize_t)n) return -1;
    /* Без ожидания: ответ ядра на GET уже в сокете. Вычитываем всё, что
       есть, — свой seq берём, чужое (запоздавшее) отбрасываем. */
    uint8_t buf[4096];
    int rc = -1;
    for (int i = 0; i < 8; i++) {
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got <= 0) break;
        int r = d2k_ct_counters_parse(buf, (size_t)got, seq, orig_pkts, reply_pkts);
        if (r == 0) { rc = 0; break; }
        if (r == 1) { rc = -1; break; }
    }
    return rc;
}

#ifdef __linux__
#include <sys/socket.h>
#include <linux/netlink.h>
int d2k_ct_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, D2K_NETLINK_NETFILTER);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) { close(fd); return -1; }
    struct sockaddr_nl a;
    memset(&a, 0, sizeof a);
    a.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) { close(fd); return -1; }
    return fd;
}
#else
int d2k_ct_open(void) { return -1; }
#endif
