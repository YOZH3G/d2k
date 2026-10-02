#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef D2K_HTTPUP_NO_MAIN /* tests include this file on non-Linux hosts */
#include <linux/netfilter_ipv4.h>
#endif

#include "d2k_httpup.h"

#define LISTEN_ADDR "0.0.0.0"
#define LISTEN_PORT 18080
#define WORKERS 6
#define QUEUE_CAP 24
#define HEADER_CAP 16384
#ifndef IDLE_MS
#define IDLE_MS 120000
#endif
#define HTTP_HEAD_MS 1200

static int pending[QUEUE_CAP];
static size_t q_read, q_write, q_count;
static uint32_t outbound_mark = 0x2f;
static pthread_mutex_t q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_cv = PTHREAD_COND_INITIALIZER;

static int send_all(int fd, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n > 0) { p += (size_t)n; len -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) { continue; }
        return -1;
    }
    return 0;
}

static int wait_readable(int fd, int ms) {
    struct pollfd p = { fd, POLLIN, 0 };
    int rc;
    do { rc = poll(&p, 1, ms); } while (rc < 0 && errno == EINTR);
    return rc > 0 && (p.revents & (POLLIN | POLLHUP)) ? 1 : 0;
}

static int read_first_request(int fd, char *buf, size_t cap, size_t *used) {
    *used = 0;
    while (*used < cap) {
        if (wait_readable(fd, 8000) != 1) { return -1; }
        ssize_t n = recv(fd, buf + *used, cap - *used, 0);
        if (n <= 0) { return -1; }
        *used += (size_t)n;
        if (*used >= 4) {
            for (size_t i = 3; i < *used; i++) {
                if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
                    buf[i - 1] == '\r' && buf[i] == '\n') { return 0; }
            }
        }
    }
    /* A large or malformed header is proxied intact, not partially parsed. */
    return 1;
}

/* GET/HEAD portal detection needs only the upstream response head. Bytes read
   beyond CRLFCRLF stay in this buffer and are relayed before the live stream. */
static int read_first_response(int fd, char *buf, size_t cap, size_t *used) {
    *used = 0;
    while (*used < cap) {
        if (wait_readable(fd, HTTP_HEAD_MS) != 1) { return *used ? 1 : -1; }
        ssize_t n = recv(fd, buf + *used, cap - *used, 0);
        if (n <= 0) { return *used ? 1 : -1; }
        *used += (size_t)n;
        if (*used >= 4) {
            for (size_t i = 3; i < *used; i++) {
                if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
                    buf[i - 1] == '\r' && buf[i] == '\n') { return 0; }
            }
        }
    }
    return 1;
}

static int upstream_connect(const struct sockaddr_in *dst) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { return -1; }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &outbound_mark, sizeof outbound_mark) != 0) {
        close(fd); return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }
    if (connect(fd, (const struct sockaddr *)dst, sizeof *dst) != 0 && errno != EINPROGRESS) {
        close(fd); return -1;
    }
    struct pollfd p = { fd, POLLOUT, 0 };
    int rc;
    do { rc = poll(&p, 1, 5000); } while (rc < 0 && errno == EINTR);
    int error = 0;
    socklen_t error_len = sizeof error;
    if (rc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error) {
        close(fd); return -1;
    }
    if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
    return fd;
}

static void relay(int client, int upstream) {
    int open_client = 1, open_upstream = 1;
    unsigned char buf[8192];
    while (open_client || open_upstream) {
        /* A closed side gets fd=-1 so poll ignores it entirely: with events=0
           Linux still reports POLLHUP/POLLERR and the loop spun at 100% CPU. */
        struct pollfd p[2] = {
            { open_client ? client : -1, POLLIN, 0 },
            { open_upstream ? upstream : -1, POLLIN, 0 }
        };
        int rc;
        do { rc = poll(p, 2, IDLE_MS); } while (rc < 0 && errno == EINTR);
        if (rc <= 0) { break; }
        for (int i = 0; i < 2; i++) {
            if (!p[i].revents) { continue; }
            int src = i == 0 ? client : upstream;
            int dst = i == 0 ? upstream : client;
            ssize_t n = recv(src, buf, sizeof buf, 0);
            if (n == 0) {
                if (i == 0) { open_client = 0; shutdown(upstream, SHUT_WR); }
                else { open_upstream = 0; shutdown(client, SHUT_WR); }
                continue;
            }
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { continue; }
                open_client = open_upstream = 0;
                break;
            }
            if (send_all(dst, buf, (size_t)n) != 0) { open_client = open_upstream = 0; break; }
        }
    }
}

#ifndef D2K_HTTPUP_NO_MAIN
static void serve_client(int client) {
    struct sockaddr_in original;
    socklen_t original_len = sizeof original;
    memset(&original, 0, sizeof original);
    if (getsockopt(client, SOL_IP, SO_ORIGINAL_DST, &original, &original_len) != 0 ||
        original.sin_family != AF_INET || original.sin_port != htons(80)) {
        close(client); return;
    }

    struct timeval timeout = { 8, 0 };
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    char request[HEADER_CAP];
    size_t request_len = 0;
    int read_rc = read_first_request(client, request, sizeof request, &request_len);
    if (read_rc < 0) { close(client); return; }

    int upstream = upstream_connect(&original);
    if (upstream < 0) { close(client); return; }
    if (request_len && send_all(upstream, request, request_len) != 0) {
        close(upstream); close(client); return;
    }
    if (read_rc == 0 && d2k_httpup_request_safe(request, request_len)) {
        char response_head[HEADER_CAP];
        size_t response_len = 0;
        int response_rc = read_first_response(upstream, response_head,
                                             sizeof response_head, &response_len);
        if (response_rc >= 0) {
            char portal_redirect[4096];
            if (d2k_httpup_portal_response(request, request_len,
                                           response_head, response_len,
                                           portal_redirect, sizeof portal_redirect)) {
                (void)send_all(client, portal_redirect, strlen(portal_redirect));
                close(upstream);
                close(client);
                return;
            }
            if (response_len && send_all(client, response_head, response_len) != 0) {
                close(upstream); close(client); return;
            }
        }
    }
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){0, 0}, sizeof(struct timeval));
    relay(client, upstream);
    close(upstream);
    close(client);
}

static void *worker(void *unused) {
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&q_mu);
        while (q_count == 0) { pthread_cond_wait(&q_cv, &q_mu); }
        int fd = pending[q_read];
        q_read = (q_read + 1) % QUEUE_CAP;
        q_count--;
        pthread_mutex_unlock(&q_mu);
        serve_client(fd);
    }
    return NULL;
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s [--port PORT] [--mark VALUE]\n", argv0);
}

int main(int argc, char **argv) {
    unsigned port = LISTEN_PORT;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            char *end = NULL; unsigned long v = strtoul(argv[++i], &end, 10);
            if (!end || *end || v == 0 || v > 65535) { usage(argv[0]); return 2; }
            port = (unsigned)v;
        } else if (strcmp(argv[i], "--mark") == 0 && i + 1 < argc) {
            char *end = NULL; unsigned long v = strtoul(argv[++i], &end, 0);
            if (!end || *end || v == 0 || v > UINT32_MAX) { usage(argv[0]); return 2; }
            outbound_mark = (uint32_t)v;
        } else { usage(argv[0]); return 2; }
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("d2khttp: socket"); return 1; }
    int one = 1;
    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(listen_fd, QUEUE_CAP) != 0) {
        perror("d2khttp: bind/listen"); close(listen_fd); return 1;
    }

    pthread_t threads[WORKERS];
    for (size_t i = 0; i < WORKERS; i++) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            fprintf(stderr, "d2khttp: cannot create worker pool\n");
            close(listen_fd); return 1;
        }
    }
    fprintf(stderr, "d2khttp: transparent listener on %s:%u\n", LISTEN_ADDR, port);
    for (;;) {
        struct pollfd p = { listen_fd, POLLIN, 0 };
        int rc;
        do { rc = poll(&p, 1, -1); } while (rc < 0 && errno == EINTR);
        if (rc <= 0) { continue; }
        int client = accept(listen_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) { continue; }
            struct timespec pause = { 0, 10000000L };
            nanosleep(&pause, NULL);
            continue;
        }
        int accepted = 0;
        pthread_mutex_lock(&q_mu);
        if (q_count < QUEUE_CAP) {
            pending[q_write] = client;
            q_write = (q_write + 1) % QUEUE_CAP;
            q_count++;
            accepted = 1;
            pthread_cond_signal(&q_cv);
        }
        pthread_mutex_unlock(&q_mu);
        if (!accepted) { close(client); }
    }
}
#endif /* D2K_HTTPUP_NO_MAIN */
