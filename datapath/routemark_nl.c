/* routemark_nl.c — RTM_GETRULE dumps, RTM_GETROUTE lookups and change
 * notifications over rtnetlink (Linux only). */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "d2k_routemark.h"

typedef int (*dump_parse)(void *out, size_t cap, size_t *n, const uint8_t *buf,
                          size_t len, int32_t *kerr);

static int parse_rules(void *out, size_t cap, size_t *n, const uint8_t *buf,
                       size_t len, int32_t *kerr) {
    return d2k_routemark_parse(out, cap, n, buf, len, kerr);
}


/* 0 — read to DONE; -1 — failed (err filled).  A family the kernel does not
   support (-EAFNOSUPPORT/-EOPNOTSUPP: no IPv6 policy rules or no IPv6) is a
   successful read of nothing (final review M-2): the rules cannot exist. */
static int dump(int fd, const uint8_t *req, size_t rl, const char *what,
                dump_parse parse, void *out, size_t cap, size_t *n,
                char *err, size_t errcap) {
    struct sockaddr_nl to;
    memset(&to, 0, sizeof to);
    to.nl_family = AF_NETLINK;
    if (sendto(fd, req, rl, 0, (struct sockaddr *)&to, sizeof to) != (ssize_t)rl) {
        snprintf(err, errcap, "%s: %s", what, strerror(errno));
        return -1;
    }
    static uint8_t buf[32768];
    /* Bounded by the dump itself (DONE) and the receive timeout; the round
       limit only stops a kernel that never ends one. */
    for (int rounds = 0; rounds < 4096; rounds++) {
        ssize_t got = recv(fd, buf, sizeof buf, 0);
        if (got < 0) {
            if (errno == EINTR) { continue; }
            snprintf(err, errcap, "%s recv: %s", what, strerror(errno));
            return -1;
        }
        int32_t kerr = 0;
        int rc = parse(out, cap, n, buf, (size_t)got, &kerr);
        if (rc == 1) { return 0; }
        if (rc < 0) {
            if (kerr == -EAFNOSUPPORT || kerr == -EOPNOTSUPP) { *n = 0; return 0; }
            if (kerr) { snprintf(err, errcap, "%s: %s", what, strerror(-kerr)); }
            else { snprintf(err, errcap, "%s: ответ не разобран", what); }
            return -1;
        }
    }
    snprintf(err, errcap, "%s: нет конца дампа", what);
    return -1;
}

static int dump_rules(int fd, uint8_t family, uint32_t seq, d2k_fwsel *sel,
                      size_t *n, char *err, size_t errcap) {
    uint8_t req[64];
    size_t rl = d2k_routemark_request(req, sizeof req, family, seq);
    return dump(fd, req, rl, family == 10 ? "RTM_GETRULE v6" : "RTM_GETRULE",
                parse_rules, sel, D2K_ROUTEMARK_MAX, n, err, errcap);
}

/* One RTM_GETROUTE lookup (review I-A: never a dump of every table).
   0 — a route with devices; 2 — a route without a device (no device gate);
   3 — no route (every outbound packet leaves elsewhere); -1 — failed. */
static int lookup_route(int fd, uint8_t family, uint32_t seq, uint32_t *oifs,
                        size_t *n, char *err, size_t errcap) {
    const char *what = family == 10 ? "маршрут IPv6" : "маршрут IPv4";
    uint8_t req[64];
    size_t rl = d2k_routemark_lookup_request(req, sizeof req, family, seq);
    struct sockaddr_nl to;
    memset(&to, 0, sizeof to);
    to.nl_family = AF_NETLINK;
    if (sendto(fd, req, rl, 0, (struct sockaddr *)&to, sizeof to) != (ssize_t)rl) {
        snprintf(err, errcap, "%s: %s", what, strerror(errno));
        return -1;
    }
    static uint8_t buf[8192];
    for (int rounds = 0; rounds < 4; rounds++) {
        ssize_t got = recv(fd, buf, sizeof buf, 0);
        if (got < 0) {
            if (errno == EINTR) { continue; }
            snprintf(err, errcap, "%s recv: %s", what, strerror(errno));
            return -1;
        }
        int32_t kerr = 0;
        int rc = d2k_routemark_lookup_parse(oifs, D2K_ROUTEMARK_OIF_MAX, n, buf,
                                            (size_t)got, &kerr);
        if (rc == 1) { return *n ? 0 : 2; }
        if (rc == 2) { *n = 0; return 3; }
        if (rc < 0) {
            if (kerr == -ENETUNREACH || kerr == -EHOSTUNREACH || kerr == -ENETDOWN ||
                kerr == -EAFNOSUPPORT) {
                *n = 0;
                return 3;
            }
            if (kerr) { snprintf(err, errcap, "%s: %s", what, strerror(-kerr)); }
            else { snprintf(err, errcap, "%s: ответ не разобран", what); }
            return -1;
        }
    }
    snprintf(err, errcap, "%s: нет ответа", what);
    return -1;
}

/* A dump socket with a receive timeout: the read happens on the service's
   single packet loop.  Without the timeout it is not used at all (rereview
   m3). */
static int dump_socket(char *err, size_t errcap) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        snprintf(err, errcap, "rtnetlink: %s", strerror(errno));
        return -1;
    }
    struct timeval tv = {0, 200000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) {
        snprintf(err, errcap, "rtnetlink SO_RCVTIMEO: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int d2k_routemark_load(d2k_routemark *r, d2k_routemark_status *st,
                       int *routes4_ok, int *routes6_ok,
                       char *err, size_t errcap) {
    d2k_routemark_status local;
    if (!st) { st = &local; }
    memset(st, 0, sizeof *st);
    if (routes4_ok) { *routes4_ok = 0; }
    if (routes6_ok) { *routes6_ok = 0; }
    d2k_fwsel v4[D2K_ROUTEMARK_MAX], v6[D2K_ROUTEMARK_MAX];
    uint32_t o4[D2K_ROUTEMARK_OIF_MAX], o6[D2K_ROUTEMARK_OIF_MAX];
    size_t n4 = 0, n6 = 0, no4 = 0, no6 = 0;
    char e[4][128];
    int ok[4] = {0, 0, 0, 0};
    int rr[4] = {0, 0, 0, 0};
    /* Each part on its own: one failing never discards another (M-2).  A
       failed dump may leave its tail in the socket, so the next part gets a
       fresh one. */
    int fd = -1;
    for (int part = 0; part < 4; part++) {
        if (fd < 0 && (fd = dump_socket(e[part], sizeof e[part])) < 0) { continue; }
        int rc;
        switch (part) {
        case 0: rc = dump_rules(fd, 2, 1, v4, &n4, e[0], sizeof e[0]); break;
        case 1: rc = dump_rules(fd, 10, 2, v6, &n6, e[1], sizeof e[1]); break;
        case 2: rc = lookup_route(fd, 2, 3, o4, &no4, e[2], sizeof e[2]); break;
        default: rc = lookup_route(fd, 10, 4, o6, &no6, e[3], sizeof e[3]); break;
        }
        rr[part] = rc;
        ok[part] = rc >= 0;
        if (rc < 0) { close(fd); fd = -1; }
    }
    if (fd >= 0) { close(fd); }
    int changed = d2k_routemark_merge(r, v4, n4, ok[0], v6, n6, ok[1], st) == 1;
    /* A route that names no device: no device gate for that family (the
       mark gate only) rather than gating everything (review minor). */
    changed |= rr[2] == 2 ? d2k_routemark_clear_oifs(r, 2)
                          : d2k_routemark_set_oifs(r, 2, o4, no4, ok[2]);
    changed |= rr[3] == 2 ? d2k_routemark_clear_oifs(r, 10)
                          : d2k_routemark_set_oifs(r, 10, o6, no6, ok[3]);
    if (routes4_ok) { *routes4_ok = rr[2] == 2 ? 2 : ok[2]; }
    if (routes6_ok) { *routes6_ok = rr[3] == 2 ? 2 : ok[3]; }
    /* The first failure names the problem. */
    for (int part = 0; part < 4; part++) {
        if (!ok[part]) { snprintf(err, errcap, "%s", e[part]); break; }
    }
    if (!ok[0] && !ok[1] && !ok[2] && !ok[3]) { return -1; }
    return changed;
}

int d2k_routemark_watch_open(char *err, size_t errcap) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) {
        snprintf(err, errcap, "rtnetlink (уведомления): %s", strerror(errno));
        return -1;
    }
    struct sockaddr_nl me;
    memset(&me, 0, sizeof me);
    me.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&me, sizeof me) != 0) {
        snprintf(err, errcap, "rtnetlink bind: %s", strerror(errno));
        close(fd);
        return -1;
    }
    static const int groups[] = {RTNLGRP_IPV4_RULE, RTNLGRP_IPV4_ROUTE,
                                 RTNLGRP_IPV6_RULE, RTNLGRP_IPV6_ROUTE};
    int joined = 0;
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++) {
        int g = groups[i];
        if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &g, sizeof g) == 0) {
            joined++;
        } else if (i < 2) {
            /* IPv4 is not optional; IPv6 groups may be missing. */
            snprintf(err, errcap, "rtnetlink группа %d: %s", g, strerror(errno));
            close(fd);
            return -1;
        }
    }
    (void)joined;
    return fd;
}

int d2k_routemark_watch_drain(int fd) {
    static uint8_t buf[8192];
    int any = 0;
    /* Bounded per wake: a notification storm (route lists loading) must not
       hold the packet loop; what is left is read on the next wake. */
    for (int reads = 0; reads < D2K_ROUTEMARK_WATCH_READS; reads++) {
        ssize_t got = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (got > 0) {
            if (!any) { any = d2k_routemark_watch_relevant(buf, (size_t)got); }
            continue;
        }
        if (got < 0 && errno == EINTR) { continue; }
        /* ENOBUFS: notifications were lost — something may have changed. */
        if (got < 0 && errno == ENOBUFS) { any = 1; continue; }
        return any;
    }
    return 1;   /* cap reached: refresh to be safe */
}
