/* test_routemark.c — which client marks select a policy route (task 47 fix
 * round 1, review I2).  Pure matcher and RTM_GETRULE dump parser; the
 * netlink socket itself is Linux-only (routemark_nl.c). */
#include <stdio.h>
#include <string.h>

#include "d2k_routemark.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "routemark:%d: %s\n", __LINE__, m); fails++; } } while (0)

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }   /* host order */
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* One RTM_NEWRULE message: fib_rule_hdr + optional FRA_FWMARK/FRA_FWMASK +
 * FRA_TABLE (always, to prove unrelated attributes are skipped). */
static size_t rule_msg(uint8_t *o, uint8_t family, int have_mark, uint32_t mark,
                       int have_mask, uint32_t mask, uint8_t action) {
    size_t n = 16 + 12;
    memset(o, 0, 128);
    w16(o + 4, 32);                 /* RTM_NEWRULE */
    o[16] = family;
    o[16 + 4] = 252;                /* table (compat byte) */
    o[16 + 7] = action;             /* FR_ACT_TO_TBL=1, BLACKHOLE=6 */
    w16(o + n, 8); w16(o + n + 2, 15); w32(o + n + 4, 4096); n += 8;  /* FRA_TABLE */
    if (have_mark) { w16(o + n, 8); w16(o + n + 2, 10); w32(o + n + 4, mark); n += 8; }
    if (have_mask) { w16(o + n, 8); w16(o + n + 2, 16); w32(o + n + 4, mask); n += 8; }
    w32(o, (uint32_t)n);
    return n;
}

static size_t done_msg(uint8_t *o) {
    memset(o, 0, 20);
    w32(o, 20); w16(o + 4, 3);       /* NLMSG_DONE */
    return 20;
}

int main(void) {
    uint8_t buf[1024];
    size_t len = 0;
    /* Keenetic 03.10: 100 fwmark 0xffffaaa lookup 4096; 101 same -> blackhole;
       1170 from <wan> lookup 16394 (no mark); IPv6 fwmark 0x100/0xff00. */
    len += rule_msg(buf + len, 2, 1, 0xffffaaa, 1, 0xffffffff, 1);
    len += rule_msg(buf + len, 2, 1, 0xffffaaa, 1, 0xffffffff, 6);
    len += rule_msg(buf + len, 2, 0, 0, 0, 0, 1);
    len += rule_msg(buf + len, 10, 1, 0x100, 1, 0xff00, 1);
    len += rule_msg(buf + len, 2, 1, 0x200, 0, 0, 1);   /* old kernels: no mask -> full */
    len += done_msg(buf + len);

    d2k_fwsel sel[D2K_ROUTEMARK_MAX];
    size_t n = 0;
    CHECK(d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, &n, buf, len) == 1, "dump parsed to DONE");
    CHECK(n == 4, "four fwmark selectors (the address rule is not one)");

    d2k_routemark rm;
    d2k_routemark_init(&rm);
    CHECK(!d2k_routemark_routed(&rm, 0xffffaaa), "no rules loaded: nothing is routed");
    CHECK(d2k_routemark_set(&rm, sel, n) == 1, "first load is a change");
    CHECK(d2k_routemark_set(&rm, sel, n) == 0, "same set again: no change (no log line)");
    CHECK(d2k_routemark_routed(&rm, 0xffffaaa), "DNSRT mark with its rule: routed");
    CHECK(!d2k_routemark_routed(&rm, 0x1), "PPPoE-style 0x1 without a rule: not routed");
    CHECK(!d2k_routemark_routed(&rm, 0x989), "a stray mark without a rule: not routed");
    CHECK(!d2k_routemark_routed(&rm, 0), "no mark: never routed");
    CHECK(d2k_routemark_routed(&rm, 0x1ff), "masked selector 0x100/0xff00 matches 0x1ff");
    CHECK(!d2k_routemark_routed(&rm, 0x2ff), "masked selector does not match 0x2ff");
    CHECK(d2k_routemark_routed(&rm, 0x200) && !d2k_routemark_routed(&rm, 0x201),
          "a mark without a mask attribute is matched exactly");

    char text[256];
    CHECK(d2k_routemark_describe(&rm, text, sizeof text) > 0 && strstr(text, "0xffffaaa"),
          "selectors can be logged");

    /* The caller's gate: own marks never count, routed marks pass through. */
    CHECK(d2k_routemark_client(&rm, 1, 0xffffaaa, 0x2e, 0x2d) == 0xffffaaa, "routed client mark");
    CHECK(d2k_routemark_client(&rm, 1, 0x1, 0x2e, 0x2d) == 0, "unrouted mark: d2k works");
    CHECK(d2k_routemark_client(&rm, 0, 0xffffaaa, 0x2e, 0x2d) == 0, "no mark attribute");

    /* Rule removed: refresh with a dump that lacks it. */
    len = 0;
    len += rule_msg(buf + len, 2, 0, 0, 0, 0, 1);
    len += done_msg(buf + len);
    n = 0;
    CHECK(d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, &n, buf, len) == 1 && n == 0,
          "dump without fwmark rules");
    CHECK(d2k_routemark_set(&rm, sel, n) == 1, "removal is a change");
    CHECK(!d2k_routemark_routed(&rm, 0xffffaaa), "rule removed: no longer routed after refresh");

    /* Malformed input never reads past the buffer and is reported. */
    uint8_t bad[24];
    memset(bad, 0, sizeof bad);
    w32(bad, 200); w16(bad + 4, 32);
    n = 0;
    CHECK(d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, &n, bad, sizeof bad) == -1, "garbage refused");
    uint8_t req[64];
    size_t rl = d2k_routemark_request(req, sizeof req, 2, 7);
    CHECK(rl >= 28 && req[16] == 2, "dump request for AF_INET");

    if (!fails) puts("routemark: selectors, matcher and refresh passed");
    return fails != 0;
}
