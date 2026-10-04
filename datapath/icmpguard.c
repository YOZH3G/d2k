/* icmpguard.c — см. d2k_icmpguard.h. Разбор чужих байтов: каждое чтение
 * ограничено длиной, которая есть, а не той, что заявлена в заголовке. */
#include <string.h>
#include "d2k_icmpguard.h"

void d2k_icmpguard_init(d2k_icmpguard *g) {
    if (g) { memset(g, 0, sizeof *g); }
}

static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }

/* Заголовок IP + первые 8 байт L4 — то, что гарантированно есть и в посылке,
 * и в цитате (RFC 792). Длины из заголовка не проверяются против n: цитата
 * обрезана по определению. 0 — не разобрано. */
typedef struct {
    uint8_t family, proto, ttl;
    const uint8_t *src, *dst, *l4;
    uint16_t ip_len, ip_id;
} ipq;

static int parse_ip(const uint8_t *p, size_t n, ipq *q) {
    if (!p || n < 1) { return 0; }
    memset(q, 0, sizeof *q);
    q->family = p[0] >> 4;
    size_t hl;
    if (q->family == 4) {
        if (n < 20) { return 0; }
        hl = (size_t)(p[0] & 15u) * 4u;
        if (hl < 20) { return 0; }
        if (u16(p + 6) & 0x1fffu) { return 0; }   /* не первый фрагмент: портов нет */
        q->proto = p[9]; q->ttl = p[8];
        q->ip_len = (uint16_t)u16(p + 2); q->ip_id = (uint16_t)u16(p + 4);
        q->src = p + 12; q->dst = p + 16;
    } else if (q->family == 6) {
        hl = 40;
        if (n < 40) { return 0; }
        q->proto = p[6]; q->ttl = p[7];
        q->ip_len = (uint16_t)u16(p + 4);
        q->src = p + 8; q->dst = p + 24;
    } else {
        return 0;
    }
    if (q->proto != 6 && q->proto != 17) { return 0; }
    if (n < hl + 8) { return 0; }
    q->l4 = p + hl;
    return 1;
}

int d2k_icmpguard_note(d2k_icmpguard *g, const uint8_t *pkt, size_t len,
                       uint8_t orig_ttl, uint64_t now_ns) {
    ipq q;
    if (!g || !parse_ip(pkt, len, &q)) { return 0; }
    if (q.ttl >= orig_ttl) { return 0; }   /* TTL не понижен — дойдёт до сервера */
    d2k_icmpguard_slot *s = &g->slot[g->next];
    g->next = (g->next + 1) % D2K_ICMPGUARD_SLOTS;
    memset(s, 0, sizeof *s);
    s->at = now_ns ? now_ns : 1;
    s->family = q.family; s->proto = q.proto; s->ttl = q.ttl;
    size_t alen = q.family == 6 ? 16 : 4;
    memcpy(s->src, q.src, alen); memcpy(s->dst, q.dst, alen);
    memcpy(s->sport, q.l4, 2); memcpy(s->dport, q.l4 + 2, 2);
    /* UDP: только длина; сумму меняет NAT, и сверять её значило бы зависеть от
       того, как ядро пересчитало цитату. */
    memcpy(s->l4word, q.l4 + 4, q.proto == 6 ? 4 : 2);
    s->ip_len = q.ip_len;
    if (q.family == 4 && q.ip_id != 0) { s->have_id = 1; s->ip_id = q.ip_id; }
    g->noted++;
    return 1;
}

int d2k_icmpguard_check(d2k_icmpguard *g, const uint8_t *pkt, size_t len,
                        uint64_t now_ns) {
    if (!g || !pkt || len < 1) { return 0; }
    const uint8_t *icmp;
    uint8_t family = pkt[0] >> 4;
    if (family == 4) {
        if (len < 20) { return 0; }
        size_t hl = (size_t)(pkt[0] & 15u) * 4u;
        if (hl < 20 || pkt[9] != 1 || (u16(pkt + 6) & 0x3fffu)) { return 0; }
        if (len < hl + 8) { return 0; }
        icmp = pkt + hl;
        if (icmp[0] != 11 || icmp[1] != 0) { return 0; }
    } else if (family == 6) {
        /* ICMPv6 сразу за основным заголовком: узлы на пути заголовков
           расширения к ошибкам не добавляют; иное — не судим. */
        if (len < 48 || pkt[6] != 58) { return 0; }
        icmp = pkt + 40;
        if (icmp[0] != 3 || icmp[1] != 0) { return 0; }
    } else {
        return 0;
    }
    size_t avail = len - (size_t)(icmp + 8 - pkt);
    ipq q;
    if (!parse_ip(icmp + 8, avail, &q) || q.family != family) { return 0; }
    size_t alen = family == 6 ? 16 : 4;
    for (size_t i = 0; i < D2K_ICMPGUARD_SLOTS; i++) {
        const d2k_icmpguard_slot *s = &g->slot[i];
        if (!s->at || now_ns < s->at || now_ns - s->at > D2K_ICMPGUARD_KEEP_NS) { continue; }
        if (s->family != family || s->proto != q.proto) { continue; }
        if (memcmp(s->src, q.src, alen) || memcmp(s->dst, q.dst, alen)) { continue; }
        if (memcmp(s->sport, q.l4, 2) || memcmp(s->dport, q.l4 + 2, 2)) { continue; }
        if (memcmp(s->l4word, q.l4 + 4, q.proto == 6 ? 4 : 2)) { continue; }
        if (s->ip_len != q.ip_len) { continue; }
        if (s->have_id && s->ip_id != q.ip_id) { continue; }
        if (q.ttl > s->ttl) { continue; }
        g->dropped++;
        return 1;
    }
    return 0;
}

uint64_t d2k_icmpguard_dropped(const d2k_icmpguard *g) { return g ? g->dropped : 0; }
uint64_t d2k_icmpguard_noted(const d2k_icmpguard *g) { return g ? g->noted : 0; }
