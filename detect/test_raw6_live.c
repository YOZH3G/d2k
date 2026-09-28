/* Linux isolated-network integration: requires NET_RAW, NET_ADMIN, ip6tables.
 * Uses loopback only. Never invoke this as an ordinary unprivileged unit test. */
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "d2k_detect.h"

struct server { int fd; int payload; int received; };
static void *serve(void *arg) {
    struct server *s = arg;
    struct pollfd p = {s->fd, POLLIN, 0};
    if (poll(&p, 1, 5000) <= 0) return NULL;
    int fd = accept(s->fd, NULL, NULL);
    if (fd < 0) return NULL;
    if (s->payload) {
        struct timeval tv = {2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        char bytes[32];
        ssize_t n = recv(fd, bytes, sizeof bytes, 0);
        s->received = n == 5 && memcmp(bytes, "hello", 5) == 0;
        if (s->received) (void)send(fd, "reply", 5, 0);
    }
    close(fd);
    return NULL;
}

int main(void) {
    for (int payload = 0; payload <= 1; payload++) {
        struct server s = {socket(AF_INET6, SOCK_STREAM, 0), payload, 0};
        assert(s.fd >= 0);
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6; addr.sin6_addr = in6addr_loopback;
        assert(bind(s.fd, (struct sockaddr *)&addr, sizeof addr) == 0);
        assert(listen(s.fd, 2) == 0);
        socklen_t len = sizeof addr;
        assert(getsockname(s.fd, (struct sockaddr *)&addr, &len) == 0);
        pthread_t thread;
        assert(pthread_create(&thread, NULL, serve, &s) == 0);
        char err[200] = {0};
        d2k_detect_stop cancel = {0};
        d2k_trigger tr = {0};
        memcpy(tr.payload, "hello", 5); tr.len = 5; tr.accept = D2K_ACCEPT_ANY;
        d2k_poison poison = {0};
        int rc = payload
            ? d2k_raw_probe_poison_family((const uint8_t *)&addr.sin6_addr, 6,
                ntohs(addr.sin6_port), &tr, &poison, 2000, 0xd200, &cancel, err, sizeof err)
            : d2k_raw_probe_handshake_family((const uint8_t *)&addr.sin6_addr, 6,
                ntohs(addr.sin6_port), 2000, 0xd200, &cancel, err, sizeof err);
        pthread_join(thread, NULL); close(s.fd);
        if (rc != 1 || (payload && !s.received)) {
            fprintf(stderr, "raw IPv6 phase %d: rc=%d received=%d %s\n",
                    payload, rc, s.received, err);
            return 1;
        }
    }
    puts("raw IPv6: native SYN/ACK and bidirectional TCP payload passed");
    return 0;
}
