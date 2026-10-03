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

int d2k_routemark_load(d2k_routemark *r, d2k_routemark_status *st,
                       char *err, size_t errcap) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        snprintf(err, errcap, "rtnetlink: %s", strerror(errno));
        return -1;
    }
    /* Bounded: the read happens on the service's single packet loop.  Without
       a receive timeout the dump is not read at all (rereview m3). */
    struct timeval tv = {0, 200000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) {
        snprintf(err, errcap, "rtnetlink SO_RCVTIMEO: %s", strerror(errno));
        close(fd);
        return -1;
    }
    d2k_fwsel v4[D2K_ROUTEMARK_MAX], v6[D2K_ROUTEMARK_MAX];
    size_t n4 = 0, n6 = 0;
    char err6[128];
    int ok4 = dump_family(fd, 2, 1, v4, &n4, err, errcap) == 0;
    int ok6 = ok4 && dump_family(fd, 10, 2, v6, &n6, err6, sizeof err6) == 0;
    close(fd);
    int rc = d2k_routemark_merge(r, v4, n4, ok4, v6, n6, ok6, st);
    if (rc < 0 && ok4) { snprintf(err, errcap, "внутренняя ошибка слияния"); }
    return rc;
}
