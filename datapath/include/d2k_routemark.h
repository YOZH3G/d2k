/* d2k_routemark.h — which client marks select a policy route (task 47).
 *
 * A client packet whose nfmark selects an `ip rule` (fwmark/mask, any table or
 * action, blackhole included) is policy-routed — Keenetic DNSRT 0xffffaaa ->
 * table 4096 / VPN.  d2k's raw sends carry its own mark and the main table, so
 * such a flow gets no plan (d2k_session_set_route_mark).  A mark no rule
 * selects (a PPPoE/QoS mark, a stray 0x989) does not stop d2k.
 *
 * The selectors come from the kernel's RTM_GETRULE dump (AF_INET, AF_INET6),
 * re-read on every rule/route change notification (d2k_routemark_watch_*) and
 * every D2K_ROUTEMARK_REFRESH_NS as a backstop.  Parsing and matching are pure
 * and tested; only the sockets (routemark_nl.c) are Linux.
 *
 * NOT ONLY MARKS (final review I-1).  A client routed by source, iif, tos or
 * uidrange carries no mark, and a raw send (d2k's mark, saddr 0) never matches
 * such a rule: it follows the main table.  So an outbound packet (OUTPUT or
 * POSTROUTING) whose output device is none of the devices of the main table's
 * default routes (RTM_GETROUTE, table 254, dst/0, unicast, multipath hops
 * included) is routed elsewhere, whatever routed it.  Until a family's routes
 * were read once there is nothing to compare with, and the device gate is off
 * for it (the mark gate still applies).
 *
 * FAIL CLOSED (final review M-2).  A read error never replaces a family's
 * selectors or devices: the previous ones stay.  Until a family's rules were
 * read once, every foreign (non-d2k) nonzero mark counts as routed.
 */
#ifndef D2K_ROUTEMARK_H
#define D2K_ROUTEMARK_H

#include <stddef.h>
#include <stdint.h>

#define D2K_ROUTEMARK_MAX 32
#define D2K_ROUTEMARK_OIF_MAX 16
#define D2K_ROUTEMARK_REFRESH_NS UINT64_C(30000000000)
/* Notifications come in bursts (a VPN coming up adds its routes one by one);
   one dump after the burst, not one per message.  The leak window this leaves
   is this long, against 30 s before notifications were read. */
#define D2K_ROUTEMARK_SETTLE_NS UINT64_C(100000000)

/* The route mark of a client that leaves through a device other than the
   main table's defaults (no routing fwmark).  d2k_routemark_routed() says
   "routed" for it, so the UDP output keeps it on the kernel path too.  A real
   nfmark of this value also reads as routed: the safe side. */
#define D2K_ROUTE_OTHER_DEV 0xffffffffu

typedef struct {
    uint32_t mark;
    uint32_t mask;
    uint8_t  family;   /* 2 = AF_INET, 10 = AF_INET6 */
} d2k_fwsel;

typedef struct {
    size_t n;
    d2k_fwsel sel[D2K_ROUTEMARK_MAX];
    uint8_t rules_read4, rules_read6;   /* that family's rules were read once */
    uint8_t oifs_read4, oifs_read6;     /* that family's routes were read once */
    size_t n_oif4, n_oif6;
    uint32_t oif4[D2K_ROUTEMARK_OIF_MAX], oif6[D2K_ROUTEMARK_OIF_MAX];
} d2k_routemark;

void d2k_routemark_init(d2k_routemark *r);

/* RTM_GETRULE dump request for one family.  Returns its length, 0 if cap is
 * too small. */
size_t d2k_routemark_request(uint8_t *o, size_t cap, uint8_t family, uint32_t seq);

/* Appends the fwmark selectors found in rtnetlink messages to out[*n..cap).
 * *n counts every selector found, also those past cap (truncation is the
 * caller's to report).  Returns 1 when NLMSG_DONE was seen, 0 when more
 * messages are expected, -1 on an error message (e.g. -EAFNOSUPPORT for a
 * family without policy rules; *kerr, optional, gets the kernel's negative
 * errno, 0 for malformed input) or malformed input.  A rule without
 * FRA_FWMASK has the kernel's default mask: all ones for a nonzero mark.
 * A `not fwmark` rule (FIB_RULE_INVERT) is not a selector: it routes every
 * mark but that one, and d2k cannot tell those apart from unmarked traffic. */
int d2k_routemark_parse(d2k_fwsel *out, size_t cap, size_t *n,
                        const uint8_t *buf, size_t len, int32_t *kerr);

/* RTM_GETROUTE dump request for one family.  Returns its length, 0 if cap is
 * too small. */
size_t d2k_routemark_routes_request(uint8_t *o, size_t cap, uint8_t family, uint32_t seq);

/* Appends to oifs[*n..cap) every distinct output device of the main table's
 * (254) default unicast routes found in RTM_NEWROUTE messages: RTA_OIF and
 * each RTA_MULTIPATH hop.  Source-specific, cloned and non-unicast defaults
 * (unreachable, blackhole) are not exits.  Return values and *kerr as
 * d2k_routemark_parse; *n counts distinct devices past cap too. */
int d2k_routemark_routes_parse(uint32_t *oifs, size_t cap, size_t *n,
                               const uint8_t *buf, size_t len, int32_t *kerr);

/* Replaces one family's default devices (family 2 or 10) when ok; a failed
 * read (ok == 0) keeps the previous ones.  Returns 1 when the set changed. */
int d2k_routemark_set_oifs(d2k_routemark *r, uint8_t family, const uint32_t *oifs,
                           size_t n, int ok);

/* Replaces the whole selector set (both families count as read).  Returns 1
 * when it differs from the previous one. */
int d2k_routemark_set(d2k_routemark *r, const d2k_fwsel *sel, size_t n);

typedef struct {
    int v4_ok;        /* the IPv4 dump succeeded */
    int v6_ok;        /* the IPv6 dump succeeded */
    int truncated;    /* more selectors than D2K_ROUTEMARK_MAX */
    size_t found;     /* selectors found in both dumps */
} d2k_routemark_status;

/* Combines the two family dumps.  A failed dump keeps that family's previous
 * selectors (final review M-2; task 47 rereview I-A), the other family is
 * still replaced.  A kernel without IPv6 policy rules (-EAFNOSUPPORT) is a
 * successful read of none: the caller passes ok6 = 1, n6 = 0.  Returns 1 when
 * the set changed, 0 when not, -1 without r. */
int d2k_routemark_merge(d2k_routemark *r, const d2k_fwsel *v4, size_t n4, int ok4,
                        const d2k_fwsel *v6, size_t n6, int ok6,
                        d2k_routemark_status *st);

/* 1 when a nonzero mark of an IPv4 (ipver 4) or IPv6 (ipver 6) packet is
 * selected by a rule of that family ((mark ^ sel) & mask == 0), when that
 * family's rules were never read (fail closed), or for D2K_ROUTE_OTHER_DEV. */
int d2k_routemark_routed(const d2k_routemark *r, uint8_t ipver, uint32_t mark);

/* The mark half of the gate: the client's mark when it is routed and not one
 * of d2k's own marks, else 0. */
uint32_t d2k_routemark_client(const d2k_routemark *r, uint8_t ipver, int have_mark,
                              uint32_t mark, uint32_t probe_mark, uint32_t own_mark);

/* The route mark d2kd hands the session (and the UDP output) for one queued
 * packet: d2k_routemark_client's mark; else, for an outbound packet (OUTPUT or
 * POSTROUTING: outbound != 0) with an output device that is not one of that
 * family's main-table default devices, D2K_ROUTE_OTHER_DEV; else 0.  Replies
 * (FORWARD/INPUT) leave toward the LAN and are never gated by device. */
uint32_t d2k_routemark_gate(const d2k_routemark *r, uint8_t ipver, int outbound,
                            int have_mark, uint32_t mark, uint32_t probe_mark,
                            uint32_t own_mark, int have_outdev, uint32_t outdev);

/* "0xffffaaa/0xffffffff v4, ..." or "нет"; returns the length written. */
size_t d2k_routemark_describe(const d2k_routemark *r, char *buf, size_t cap);

/* Linux (routemark_nl.c): reads the rules and the main-table default
 * devices of both families and merges them into r (a failed part keeps its
 * previous value).  st->v4_ok/v6_ok tell the rule dumps, routes4_ok/routes6_ok
 * (optional) the route dumps.  Returns 1 when the selectors or devices
 * changed, 0 when unchanged, -1 when nothing could be read (err filled).
 * Never blocks: a socket without a receive timeout is not read at all. */
int d2k_routemark_load(d2k_routemark *r, d2k_routemark_status *st,
                       int *routes4_ok, int *routes6_ok,
                       char *err, size_t errcap);

/* Linux: a nonblocking rtnetlink socket subscribed to IPv4/IPv6 rule and
 * route changes (RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, RTNLGRP_IPV4_ROUTE,
 * RTNLGRP_IPV6_ROUTE) for the packet loop's poll.  -1 on failure (err).
 * A group the kernel lacks (no IPv6) is skipped. */
int d2k_routemark_watch_open(char *err, size_t errcap);
/* Reads everything pending without blocking.  1 when anything changed (or
 * the socket overran: something may have), 0 when nothing was pending. */
int d2k_routemark_watch_drain(int fd);

#endif
