#include <stdio.h>
#include <string.h>

#include "d2k_routemark.h"
#include "d2k_nl.h"

/* linux/rtnetlink.h, linux/fib_rules.h */
#define RM_RTM_NEWRULE 32
#define RM_RTM_GETRULE 34
#define RM_NLM_F_DUMP  0x300
#define RM_FIB_HDR     12u      /* struct fib_rule_hdr */
#define RM_FRA_FWMARK  10
#define RM_FRA_FWMASK  16
#define RM_FIB_RULE_INVERT 0x2u
/* linux/rtnetlink.h: struct rtmsg and its attributes */
#define RM_RTM_NEWROUTE 24
#define RM_RTM_DELROUTE 25
#define RM_RTM_GETROUTE 26
#define RM_RTM_DELRULE  33
#define RM_RTA_DST      1
#define RM_RTMSG       12u
#define RM_RTA_OIF      4
#define RM_RTA_MULTIPATH 9
#define RM_RTN_UNICAST  1
#define RM_RTNH_LEN     8u      /* struct rtnexthop */

static uint16_t rd16h(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32h(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static void wr16h(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void wr32h(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

void d2k_routemark_init(d2k_routemark *r) {
    if (r) { memset(r, 0, sizeof *r); }
}

size_t d2k_routemark_request(uint8_t *o, size_t cap, uint8_t family, uint32_t seq) {
    size_t len = D2K_NLMSG_HDRLEN + RM_FIB_HDR;
    if (!o || cap < len) { return 0; }
    memset(o, 0, len);
    wr32h(o, (uint32_t)len);
    wr16h(o + 4, RM_RTM_GETRULE);
    wr16h(o + 6, D2K_NLM_F_REQUEST | RM_NLM_F_DUMP);
    wr32h(o + 8, seq);
    o[D2K_NLMSG_HDRLEN] = family;
    return len;
}

/* Kernel errno of an NLMSG_ERROR body (negative), 0 when unreadable. */
static int32_t nl_error(const d2k_nl_msg *m) {
    return m->body_len >= 4 ? (int32_t)rd32h(m->body) : 0;
}

int d2k_routemark_parse(d2k_fwsel *out, size_t cap, size_t *n,
                        const uint8_t *buf, size_t len, int32_t *kerr) {
    if (kerr) { *kerr = 0; }
    if (!out || !n || !buf) { return -1; }
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    size_t consumed = 0;
    while (d2k_nl_next(&it, &m)) {
        consumed = (size_t)(m.body - buf) + m.body_len;
        if (m.type == D2K_NLMSG_DONE) { return 1; }
        if (m.type == D2K_NLMSG_ERROR) {
            if (kerr) { *kerr = nl_error(&m); }
            return -1;
        }
        if (m.type != RM_RTM_NEWRULE || m.body_len < RM_FIB_HDR) { continue; }
        uint8_t family = m.body[0];
        uint32_t rflags = rd32h(m.body + 8);
        int have_mark = 0, have_mask = 0;
        uint32_t mark = 0, mask = 0;
        size_t off = RM_FIB_HDR;
        while (off + D2K_NLA_HDRLEN <= m.body_len) {
            uint16_t alen = rd16h(m.body + off);
            uint16_t atype = rd16h(m.body + off + 2) & D2K_NLA_TYPE_MASK;
            if (alen < D2K_NLA_HDRLEN || alen > m.body_len - off) { return -1; }
            if (alen >= 8 && atype == RM_FRA_FWMARK) { mark = rd32h(m.body + off + 4); have_mark = 1; }
            if (alen >= 8 && atype == RM_FRA_FWMASK) { mask = rd32h(m.body + off + 4); have_mask = 1; }
            off += ((size_t)alen + 3u) & ~(size_t)3u;
        }
        if (!have_mask && have_mark && mark) { mask = 0xffffffffu; }
        if ((!have_mark && !have_mask) || mask == 0) { continue; }
        if (rflags & RM_FIB_RULE_INVERT) { continue; }   /* `not fwmark` */
        if (*n < cap) {
            out[*n].mark = mark & mask;
            out[*n].mask = mask;
            out[*n].family = family;
        }
        (*n)++;
    }
    /* The iterator stops on garbage as well as at the end: anything left
       unread is malformed. */
    return (len - consumed) < 4 ? 0 : -1;   /* at most an alignment tail */
}

/* Probe destinations: documentation prefixes (RFC 5737, RFC 3849) — no
   route list carries them, so the answer is the route a raw send to an
   arbitrary Internet address takes. */
static const uint8_t PROBE4[4] = {192, 0, 2, 1};
static const uint8_t PROBE6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

size_t d2k_routemark_lookup_request(uint8_t *o, size_t cap, uint8_t family, uint32_t seq) {
    size_t al = family == 10 ? 16 : 4;
    size_t len = D2K_NLMSG_HDRLEN + RM_RTMSG + D2K_NLA_HDRLEN + al;
    if (!o || cap < len || (family != 2 && family != 10)) { return 0; }
    memset(o, 0, len);
    wr32h(o, (uint32_t)len);
    wr16h(o + 4, RM_RTM_GETROUTE);
    wr16h(o + 6, D2K_NLM_F_REQUEST);          /* one lookup, not a dump */
    wr32h(o + 8, seq);
    uint8_t *m = o + D2K_NLMSG_HDRLEN;
    m[0] = family;
    m[1] = (uint8_t)(al * 8);                 /* dst_len */
    uint8_t *a = m + RM_RTMSG;
    wr16h(a, (uint16_t)(D2K_NLA_HDRLEN + al));
    wr16h(a + 2, RM_RTA_DST);
    memcpy(a + D2K_NLA_HDRLEN, family == 10 ? PROBE6 : PROBE4, al);
    return len;
}

static void add_oif(uint32_t *oifs, size_t cap, size_t *n, uint32_t oif) {
    if (!oif) { return; }
    size_t have = *n < cap ? *n : cap;
    for (size_t i = 0; i < have; i++) { if (oifs[i] == oif) { return; } }
    if (*n < cap) { oifs[*n] = oif; }
    (*n)++;
}

/* Walks one route message's attributes: the device and multipath hops.
   -1 on a malformed message. */
static int route_oifs(const uint8_t *b, size_t blen, uint32_t *oifs, size_t cap, size_t *n) {
    size_t off = RM_RTMSG;
    while (off + D2K_NLA_HDRLEN <= blen) {
        uint16_t alen = rd16h(b + off);
        uint16_t atype = rd16h(b + off + 2) & D2K_NLA_TYPE_MASK;
        if (alen < D2K_NLA_HDRLEN || alen > blen - off) { return -1; }
        if (alen >= 8 && atype == RM_RTA_OIF) { add_oif(oifs, cap, n, rd32h(b + off + 4)); }
        if (atype == RM_RTA_MULTIPATH) {
            const uint8_t *mp = b + off + 4;
            size_t mp_len = (size_t)alen - 4, h = 0;
            while (h + RM_RTNH_LEN <= mp_len) {
                uint16_t nl = rd16h(mp + h);
                if (nl < RM_RTNH_LEN || nl > mp_len - h) { return -1; }
                add_oif(oifs, cap, n, rd32h(mp + h + 4));
                h += ((size_t)nl + 3u) & ~(size_t)3u;
            }
        }
        off += ((size_t)alen + 3u) & ~(size_t)3u;
    }
    return 0;
}

int d2k_routemark_lookup_parse(uint32_t *oifs, size_t cap, size_t *n,
                               const uint8_t *buf, size_t len, int32_t *kerr) {
    if (kerr) { *kerr = 0; }
    if (!oifs || !n || !buf) { return -1; }
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    size_t consumed = 0;
    while (d2k_nl_next(&it, &m)) {
        consumed = (size_t)(m.body - buf) + m.body_len;
        if (m.type == D2K_NLMSG_ERROR) {
            if (kerr) { *kerr = nl_error(&m); }
            return -1;
        }
        if (m.type != RM_RTM_NEWROUTE || m.body_len < RM_RTMSG) { continue; }
        if (m.body[7] != RM_RTN_UNICAST) { return 2; }   /* unreachable, prohibit... */
        return route_oifs(m.body, m.body_len, oifs, cap, n) == 0 ? 1 : -1;
    }
    return (len - consumed) < 4 ? 0 : -1;
}

int d2k_routemark_watch_relevant(const uint8_t *buf, size_t len) {
    if (!buf) { return 0; }
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    size_t consumed = 0;
    while (d2k_nl_next(&it, &m)) {
        consumed = (size_t)(m.body - buf) + m.body_len;
        if (m.type == RM_RTM_NEWRULE || m.type == RM_RTM_DELRULE) { return 1; }
        if ((m.type == RM_RTM_NEWROUTE || m.type == RM_RTM_DELROUTE) &&
            (m.body_len < RM_RTMSG || m.body[1] == 0)) {
            return 1;   /* a default route (or unreadable: refresh to be safe) */
        }
    }
    return (len - consumed) < 4 ? 0 : 1;
}

int d2k_routemark_clear_oifs(d2k_routemark *r, uint8_t family) {
    if (!r || (family != 2 && family != 10)) { return 0; }
    uint8_t *read = family == 10 ? &r->oifs_read6 : &r->oifs_read4;
    int changed = *read;
    *read = 0;
    if (family == 10) { r->n_oif6 = 0; } else { r->n_oif4 = 0; }
    return changed;
}

int d2k_routemark_set_oifs(d2k_routemark *r, uint8_t family, const uint32_t *oifs,
                           size_t n, int ok) {
    if (!r || !ok || (family != 2 && family != 10)) { return 0; }
    if (n > D2K_ROUTEMARK_OIF_MAX) { n = D2K_ROUTEMARK_OIF_MAX; }
    uint32_t *dst = family == 10 ? r->oif6 : r->oif4;
    size_t *dn = family == 10 ? &r->n_oif6 : &r->n_oif4;
    uint8_t *read = family == 10 ? &r->oifs_read6 : &r->oifs_read4;
    int changed = !*read || *dn != n || (n && memcmp(dst, oifs, n * sizeof *oifs) != 0);
    *dn = n;
    if (n) { memcpy(dst, oifs, n * sizeof *oifs); }
    *read = 1;
    return changed;
}

int d2k_routemark_set(d2k_routemark *r, const d2k_fwsel *sel, size_t n) {
    if (!r) { return 0; }
    r->rules_read4 = r->rules_read6 = 1;
    if (n > D2K_ROUTEMARK_MAX) { n = D2K_ROUTEMARK_MAX; }
    int changed = n != r->n;
    for (size_t i = 0; !changed && i < n; i++) {
        changed = sel[i].mark != r->sel[i].mark || sel[i].mask != r->sel[i].mask ||
                  sel[i].family != r->sel[i].family;
    }
    r->n = n;
    if (n) { memcpy(r->sel, sel, n * sizeof *sel); }
    return changed;
}

int d2k_routemark_merge(d2k_routemark *r, const d2k_fwsel *v4, size_t n4, int ok4,
                        const d2k_fwsel *v6, size_t n6, int ok6,
                        d2k_routemark_status *st) {
    d2k_routemark_status local;
    if (!st) { st = &local; }
    memset(st, 0, sizeof *st);
    st->v4_ok = ok4;
    st->v6_ok = ok6;
    if (!r) { return -1; }
    /* A failed family keeps what it had: take its previous selectors. */
    d2k_fwsel prev[D2K_ROUTEMARK_MAX];
    size_t np = r->n;
    memcpy(prev, r->sel, np * sizeof *prev);
    d2k_fwsel all[D2K_ROUTEMARK_MAX];
    size_t k = 0, found = 0;
    if (ok4) {
        found += n4;
        for (size_t i = 0; i < n4 && k < D2K_ROUTEMARK_MAX; i++) { all[k++] = v4[i]; }
    } else {
        for (size_t i = 0; i < np; i++) {
            if (prev[i].family != 10) { found++; if (k < D2K_ROUTEMARK_MAX) { all[k++] = prev[i]; } }
        }
    }
    if (ok6) {
        found += n6;
        for (size_t i = 0; i < n6 && k < D2K_ROUTEMARK_MAX; i++) { all[k++] = v6[i]; }
    } else {
        for (size_t i = 0; i < np; i++) {
            if (prev[i].family == 10) { found++; if (k < D2K_ROUTEMARK_MAX) { all[k++] = prev[i]; } }
        }
    }
    st->found = found;
    st->truncated = found > D2K_ROUTEMARK_MAX;
    uint8_t r4 = r->rules_read4 || ok4, r6 = r->rules_read6 || ok6;
    int changed = d2k_routemark_set(r, all, k);
    r->rules_read4 = r4;
    r->rules_read6 = r6;
    return changed;
}

int d2k_routemark_routed(const d2k_routemark *r, uint8_t ipver, uint32_t mark) {
    if (!r || !mark) { return 0; }
    if (mark == D2K_ROUTE_OTHER_DEV) { return 1; }
    uint8_t family = ipver == 6 ? 10 : 2;
    if (!(family == 10 ? r->rules_read6 : r->rules_read4)) { return 1; }   /* fail closed */
    for (size_t i = 0; i < r->n; i++) {
        if (r->sel[i].family == family &&
            ((mark ^ r->sel[i].mark) & r->sel[i].mask) == 0) { return 1; }
    }
    return 0;
}

uint32_t d2k_routemark_client(const d2k_routemark *r, uint8_t ipver, int have_mark,
                              uint32_t mark, uint32_t probe_mark, uint32_t own_mark) {
    if (!have_mark || !mark || mark == probe_mark || mark == own_mark) { return 0; }
    return d2k_routemark_routed(r, ipver, mark) ? mark : 0;
}

uint32_t d2k_routemark_gate(const d2k_routemark *r, uint8_t ipver, int outbound,
                            int have_mark, uint32_t mark, uint32_t probe_mark,
                            uint32_t own_mark, int have_outdev, uint32_t outdev) {
    uint32_t m = d2k_routemark_client(r, ipver, have_mark, mark, probe_mark, own_mark);
    if (m || !r || !outbound || !have_outdev) { return m; }
    int v6 = ipver == 6;
    if (!(v6 ? r->oifs_read6 : r->oifs_read4)) { return 0; }   /* nothing to compare */
    const uint32_t *o = v6 ? r->oif6 : r->oif4;
    size_t n = v6 ? r->n_oif6 : r->n_oif4;
    for (size_t i = 0; i < n; i++) { if (o[i] == outdev) { return 0; } }
    return D2K_ROUTE_OTHER_DEV;
}

size_t d2k_routemark_describe(const d2k_routemark *r, char *buf, size_t cap) {
    if (!buf || !cap) { return 0; }
    buf[0] = 0;
    size_t w = 0;
    if (!r || !r->n) {
        int k = snprintf(buf, cap, "нет");
        return k > 0 ? (size_t)k : 0;
    }
    for (size_t i = 0; i < r->n && w < cap; i++) {
        int k = snprintf(buf + w, cap - w, "%s0x%x/0x%x %s", i ? ", " : "",
                         r->sel[i].mark, r->sel[i].mask,
                         r->sel[i].family == 10 ? "v6" : "v4");
        if (k < 0) { break; }
        w += (size_t)k;
    }
    return w < cap ? w : cap - 1;
}
