/* d2k_routemark.h — which client marks select a policy route (task 47).
 *
 * A client packet whose nfmark selects an `ip rule` (fwmark/mask, any table or
 * action, blackhole included) is policy-routed — Keenetic DNSRT 0xffffaaa ->
 * table 4096 / VPN.  d2k's raw sends carry its own mark and the main table, so
 * such a flow gets no plan (d2k_session_set_route_mark).  A mark no rule
 * selects (a PPPoE/QoS mark, a stray 0x989) does not stop d2k.
 *
 * The selectors come from the kernel's RTM_GETRULE dump (AF_INET, AF_INET6),
 * re-read every D2K_ROUTEMARK_REFRESH_NS.  Parsing and matching are pure and
 * tested; only the socket (routemark_nl.c) is Linux.
 */
#ifndef D2K_ROUTEMARK_H
#define D2K_ROUTEMARK_H

#include <stddef.h>
#include <stdint.h>

#define D2K_ROUTEMARK_MAX 32
#define D2K_ROUTEMARK_REFRESH_NS UINT64_C(30000000000)

typedef struct {
    uint32_t mark;
    uint32_t mask;
    uint8_t  family;   /* 2 = AF_INET, 10 = AF_INET6 */
} d2k_fwsel;

typedef struct {
    size_t n;
    d2k_fwsel sel[D2K_ROUTEMARK_MAX];
} d2k_routemark;

void d2k_routemark_init(d2k_routemark *r);

/* RTM_GETRULE dump request for one family.  Returns its length, 0 if cap is
 * too small. */
size_t d2k_routemark_request(uint8_t *o, size_t cap, uint8_t family, uint32_t seq);

/* Appends the fwmark selectors found in rtnetlink messages to out[*n..cap).
 * Returns 1 when NLMSG_DONE was seen, 0 when more messages are expected, -1
 * on an error message or malformed input.  A rule without FRA_FWMASK has the
 * kernel's default mask: all ones for a nonzero mark. */
int d2k_routemark_parse(d2k_fwsel *out, size_t cap, size_t *n,
                        const uint8_t *buf, size_t len);

/* Replaces the selector set.  Returns 1 when it differs from the previous one. */
int d2k_routemark_set(d2k_routemark *r, const d2k_fwsel *sel, size_t n);

/* 1 when a nonzero mark is selected by some rule ((mark ^ sel) & mask == 0). */
int d2k_routemark_routed(const d2k_routemark *r, uint32_t mark);

/* The route mark d2kd hands the session for one queued packet: the client's
 * mark when it is routed and not one of d2k's own marks, else 0. */
uint32_t d2k_routemark_client(const d2k_routemark *r, int have_mark, uint32_t mark,
                              uint32_t probe_mark, uint32_t own_mark);

/* "0xffffaaa/0xffffffff v4, ..." or "нет"; returns the length written. */
size_t d2k_routemark_describe(const d2k_routemark *r, char *buf, size_t cap);

/* Linux (routemark_nl.c): reads both families and sets r.  Returns 1 when the
 * set changed, 0 when unchanged, -1 on failure (r untouched, err filled). */
int d2k_routemark_load(d2k_routemark *r, char *err, size_t errcap);

#endif
