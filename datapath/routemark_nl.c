/* routemark_nl.c — RTM_GETRULE dump over rtnetlink (Linux only). */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/netlink.h>

#include "d2k_routemark.h"

static int dump_family(int fd, uint8_t family, uint32_t seq, d2k_fwsel *sel,
                       size_t *n, char *err, size_t errcap) {
    uint8_t req[64];
    size_t rl = d2k_routemark_request(req, sizeof req, family, seq);
    struct sockaddr_nl to;
    memset(&to, 0, sizeof to);
    to.nl_family = AF_NETLINK;
    if (sendto(fd, req, rl, 0, (struct sockaddr *)&to, sizeof to) != (ssize_t)rl) {
        snprintf(err, errcap, "RTM_GETRULE: %s", strerror(errno));
        return -1;
    }
    static uint8_t buf[32768];
    for (int rounds = 0; rounds < 64; rounds++) {
        ssize_t got = recv(fd, buf, sizeof buf, 0);
        if (got < 0) {
            if (errno == EINTR) { continue; }
            snprintf(err, errcap, "RTM_GETRULE recv: %s", strerror(errno));
            return -1;
        }
        int rc = d2k_routemark_parse(sel, D2K_ROUTEMARK_MAX, n, buf, (size_t)got);
        if (rc == 1) { return 0; }
        if (rc < 0) { snprintf(err, errcap, "RTM_GETRULE: ответ не разобран"); return -1; }
    }
    snprintf(err, errcap, "RTM_GETRULE: нет конца дампа");
    return -1;
}

int d2k_routemark_load(d2k_routemark *r, char *err, size_t errcap) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        snprintf(err, errcap, "rtnetlink: %s", strerror(errno));
        return -1;
    }
    /* Bounded: the read happens on the service's single loop. */
    struct timeval tv = {0, 200000};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    d2k_fwsel sel[D2K_ROUTEMARK_MAX];
    size_t n = 0;
    int rc = dump_family(fd, 2, 1, sel, &n, err, errcap);
    if (rc == 0) { rc = dump_family(fd, 10, 2, sel, &n, err, errcap); }
    close(fd);
    if (rc != 0) { return -1; }
    return d2k_routemark_set(r, sel, n);
}
