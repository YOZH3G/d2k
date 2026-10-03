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

int d2k_routemark_parse(d2k_fwsel *out, size_t cap, size_t *n,
                        const uint8_t *buf, size_t len) {
    if (!out || !n || !buf) { return -1; }
    d2k_nl_iter it;
    d2k_nl_msg m;
    d2k_nl_iter_init(&it, buf, len);
    size_t consumed = 0;
    while (d2k_nl_next(&it, &m)) {
        consumed = (size_t)(m.body - buf) + m.body_len;
        if (m.type == D2K_NLMSG_DONE) { return 1; }
        if (m.type == D2K_NLMSG_ERROR) { return -1; }
        if (m.type != RM_RTM_NEWRULE || m.body_len < RM_FIB_HDR) { continue; }
        uint8_t family = m.body[0];
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
        if (*n < cap) {
            out[*n].mark = mark & mask;
            out[*n].mask = mask;
            out[*n].family = family;
            (*n)++;
        }
    }
    /* The iterator stops on garbage as well as at the end: anything left
       unread is malformed. */
    return (len - consumed) < 4 ? 0 : -1;   /* at most an alignment tail */
}

int d2k_routemark_set(d2k_routemark *r, const d2k_fwsel *sel, size_t n) {
    if (!r) { return 0; }
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

int d2k_routemark_routed(const d2k_routemark *r, uint32_t mark) {
    if (!r || !mark) { return 0; }
    for (size_t i = 0; i < r->n; i++) {
        if (((mark ^ r->sel[i].mark) & r->sel[i].mask) == 0) { return 1; }
    }
    return 0;
}

uint32_t d2k_routemark_client(const d2k_routemark *r, int have_mark, uint32_t mark,
                              uint32_t probe_mark, uint32_t own_mark) {
    if (!have_mark || !mark || mark == probe_mark || mark == own_mark) { return 0; }
    return d2k_routemark_routed(r, mark) ? mark : 0;
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
