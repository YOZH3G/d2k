/* d2k-gate — проводник сетевой установки D2K через VPS.
 *
 * ЗАЧЕМ. С части линий в России не доходят GitHub (raw, релизы), пакетный
 * сервер Entware и сервер пакетов OpenWrt. Установщик, ночное обновление и
 * пакетные менеджеры роутера идут сперва через этот сервис, а если он не
 * ответил — напрямую, как раньше.
 *
 * ЧТО ЭТО. Подмножество HTTP-прокси, которое понимают curl, wget, opkg и apk
 * без особых настроек (переменные http_proxy/https_proxy):
 *   - CONNECT имя:443 — только к именам из списка ниже. Дальше байты идут
 *     сквозь, TLS остаётся между роутером и настоящим сервером: сертификат
 *     проверяется на имени GitHub (OpenWrt), подменить ответ этот сервис не
 *     может;
 *   - GET/HEAD http://имя/путь — открытый HTTP только к тем же именам и
 *     только на 80: так ходит Entware (bin.entware.net). Запрос
 *     пересобирается в обычный вид с Connection: close.
 * Всё прочее — отказ. Открытым прокси сервис не бывает: имена фиксированы,
 * адрес назначения он определяет сам и к частным сетям не подключается.
 *
 * Пределы — соединений, частоты с одного адреса и всего, срок на заголовок,
 * на подключение и на простой — чтобы сервис нельзя было занять целиком.
 *
 *   d2k-gate [--port 9444]
 */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0     /* macOS: SIGPIPE и так выключен в main */
#endif

#define GATE_PORT        9444
#define HEAD_MAX         8192
#define HOST_MAX         256
#define PATH_MAX_LEN     4096
#define CONN_MAX         128     /* одновременных соединений всего */
#define PER_IP_PER_MIN   180     /* установка — десятки загрузок подряд */
#define TOTAL_PER_MIN    6000
#define RATE_SLOTS       1024
#define HEAD_TIMEOUT_MS  15000
#define CONNECT_TIMEOUT_MS 10000
#define IDLE_TIMEOUT_MS  120000
#define RELAY_BUF        16384

/* Имена, ради которых сервис существует. Точное совпадение, без масок:
   маска на *.githubusercontent.com пропустила бы и чужие страницы. */
static const char *const allowed_hosts[] = {
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "bin.entware.net",
    "downloads.openwrt.org",
    NULL
};

typedef enum { REQ_BAD = 0, REQ_CONNECT, REQ_PLAIN } req_kind;

typedef struct {
    req_kind kind;
    char     method[8];
    char     host[HOST_MAX];
    unsigned port;
    char     path[PATH_MAX_LEN];
    size_t   head_len;   /* байт заголовка вместе с пустой строкой */
} gate_req;

/* Имя из списка: без учёта регистра, одна завершающая точка допустима. */
static int host_allowed(const char *host) {
    char h[HOST_MAX];
    size_t n = strlen(host);
    if (n == 0 || n >= sizeof h) return 0;
    memcpy(h, host, n + 1);
    if (h[n - 1] == '.') h[--n] = '\0';
    for (size_t i = 0; allowed_hosts[i]; i++)
        if (!strcasecmp(h, allowed_hosts[i])) return 1;
    return 0;
}

/* Имя — только буквы, цифры, точка и дефис: IP-литерал и прочее отсекаются
   до списка, чтобы сравнение не зависело от того, как записан адрес. */
static int host_syntax_ok(const char *h) {
    if (!h[0]) return 0;
    for (const char *p = h; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-')) return 0;
    }
    return 1;
}

static int parse_port(const char *s, size_t n, unsigned *port) {
    if (n == 0 || n > 5) return -1;
    unsigned v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (unsigned)(s[i] - '0');
    }
    if (v == 0 || v > 65535) return -1;
    *port = v;
    return 0;
}

/* host[:port] из [s, s+n). Порт по умолчанию — def_port. */
static int split_hostport(const char *s, size_t n, unsigned def_port,
                          char *host, size_t hcap, unsigned *port) {
    const char *colon = memchr(s, ':', n);
    size_t hn = colon ? (size_t)(colon - s) : n;
    if (hn == 0 || hn >= hcap) return -1;
    memcpy(host, s, hn); host[hn] = '\0';
    if (!host_syntax_ok(host)) return -1;
    if (colon) return parse_port(colon + 1, n - hn - 1, port);
    *port = def_port;
    return 0;
}

/* Разбор заголовка запроса. 0 — разобран, -1 — заголовок ещё не целый,
   -2 — запрос не тот, что сервис обслуживает (400). */
static int parse_head(const char *buf, size_t len, gate_req *r) {
    memset(r, 0, sizeof *r);
    const char *end = NULL;
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = buf + i + 4; break;
        }
    if (!end) return -1;
    r->head_len = (size_t)(end - buf);
    const char *le = memchr(buf, '\r', r->head_len);
    if (!le) return -2;
    const char *sp1 = memchr(buf, ' ', (size_t)(le - buf));
    if (!sp1) return -2;
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(le - sp1 - 1));
    if (!sp2) return -2;
    size_t ml = (size_t)(sp1 - buf);
    if (ml == 0 || ml >= sizeof r->method) return -2;
    memcpy(r->method, buf, ml); r->method[ml] = '\0';
    if ((size_t)(le - sp2 - 1) != 8 || strncmp(sp2 + 1, "HTTP/1.", 7) != 0) return -2;
    const char *t = sp1 + 1;
    size_t tn = (size_t)(sp2 - t);
    if (!strcmp(r->method, "CONNECT")) {
        if (split_hostport(t, tn, 0, r->host, sizeof r->host, &r->port) != 0 || !r->port)
            return -2;
        r->kind = REQ_CONNECT;
        return 0;
    }
    if (strcmp(r->method, "GET") && strcmp(r->method, "HEAD")) return -2;
    if (tn < 8 || strncasecmp(t, "http://", 7) != 0) return -2;
    t += 7; tn -= 7;
    const char *slash = memchr(t, '/', tn);
    size_t hp = slash ? (size_t)(slash - t) : tn;
    if (split_hostport(t, hp, 80, r->host, sizeof r->host, &r->port) != 0) return -2;
    size_t pn = tn - hp;
    if (pn == 0) { strcpy(r->path, "/"); }
    else {
        if (pn >= sizeof r->path) return -2;
        memcpy(r->path, slash, pn); r->path[pn] = '\0';
    }
    r->kind = REQ_PLAIN;
    return 0;
}

/* Можно ли этот запрос обслужить: имя из списка и свой порт для вида. */
static int request_allowed(const gate_req *r) {
    if (!host_allowed(r->host)) return 0;
    if (r->kind == REQ_CONNECT) return r->port == 443;
    if (r->kind == REQ_PLAIN) return r->port == 80;
    return 0;
}

static int header_is(const char *line, size_t n, const char *name) {
    size_t k = strlen(name);
    return n > k && line[k] == ':' && !strncasecmp(line, name, k);
}

/* Обычный запрос к серверу из запроса к прокси: путь вместо полного адреса,
   свой Host, без Proxy-* и Connection/Keep-Alive, с Connection: close.
   Длина собранного или -1, если не поместилось. */
static long build_origin_request(const gate_req *r, const char *head,
                                 char *out, size_t cap) {
    size_t o = 0;
    int w = snprintf(out, cap, "%s %s HTTP/1.1\r\nHost: %s\r\n", r->method, r->path, r->host);
    if (w < 0 || (size_t)w >= cap) return -1;
    o = (size_t)w;
    const char *p = memchr(head, '\n', r->head_len);
    if (!p) return -1;
    p++;
    const char *end = head + r->head_len - 2;   /* перед финальной пустой строкой */
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        size_t n = (size_t)(nl + 1 - p);
        size_t ln = n >= 2 && p[n - 2] == '\r' ? n - 2 : n - 1;
        if (!(header_is(p, ln, "Host") || header_is(p, ln, "Proxy-Connection") ||
              header_is(p, ln, "Proxy-Authorization") || header_is(p, ln, "Connection") ||
              header_is(p, ln, "Keep-Alive"))) {
            if (o + n >= cap) return -1;
            memcpy(out + o, p, n); o += n;
        }
        p = nl + 1;
    }
    static const char tail[] = "Connection: close\r\n\r\n";
    if (o + sizeof tail - 1 >= cap) return -1;
    memcpy(out + o, tail, sizeof tail - 1);
    return (long)(o + sizeof tail - 1);
}

/* Только публичные адреса: имена из списка публичные, но адрес решает DNS
   VPS, и в частную сеть самого VPS сервис ходить не должен ни при каком
   ответе резолвера. */
/* Адрес IPv4 в порядке хоста. Отдельной функцией, а не рекурсией через
   struct sockaddr: собранный на стеке sockaddr_in, прочитанный как sockaddr,
   нарушает строгий алиасинг, и gcc -O2 на Linux вправе прочитать sa_family
   до записи — ::ffff:8.8.8.8 становился «не публичным» (CI 15.10.2026). */
static int v4_public(uint32_t a) {
    uint8_t b0 = (uint8_t)(a >> 24), b1 = (uint8_t)(a >> 16);
    if (b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224) return 0;
    if (b0 == 169 && b1 == 254) return 0;
    if (b0 == 172 && (b1 & 0xf0) == 16) return 0;
    if (b0 == 192 && b1 == 168) return 0;
    if (b0 == 100 && (b1 & 0xc0) == 64) return 0;   /* 100.64.0.0/10 */
    return 1;
}

static int addr_public(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return v4_public(ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr));
    }
    if (sa->sa_family == AF_INET6) {
        const uint8_t *b = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
        static const uint8_t zero[16];
        if (!memcmp(b, zero, 15) && (b[15] == 0 || b[15] == 1)) return 0;  /* :: и ::1 */
        if (b[0] == 0xff) return 0;                         /* multicast */
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 0; /* fe80::/10 */
        if ((b[0] & 0xfe) == 0xfc) return 0;                 /* fc00::/7 */
        static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (!memcmp(b, mapped, 12)) {
            return v4_public((uint32_t)b[12] << 24 | (uint32_t)b[13] << 16 |
                             (uint32_t)b[14] << 8 | b[15]);
        }
        return 1;
    }
    return 0;
}

/* ---- частота: на адрес и всего, окно в минуту ---- */
typedef struct { uint32_t ip; time_t window; uint32_t count; } rate_slot;
typedef struct {
    pthread_mutex_t mu;
    rate_slot slots[RATE_SLOTS];
    time_t   total_window;
    uint32_t total_count;
} rate_limit;

static int rate_allow(rate_limit *l, uint32_t ip, time_t now) {
    pthread_mutex_lock(&l->mu);
    int ok = 1;
    time_t w = now / 60;
    if (l->total_window != w) { l->total_window = w; l->total_count = 0; }
    if (l->total_count >= TOTAL_PER_MIN) ok = 0;
    rate_slot *s = &l->slots[(ip * 2654435761u) % RATE_SLOTS];
    if (ok) {
        if (s->ip != ip || s->window != w) { s->ip = ip; s->window = w; s->count = 0; }
        if (s->count >= PER_IP_PER_MIN) ok = 0;
    }
    if (ok) { s->count++; l->total_count++; }
    pthread_mutex_unlock(&l->mu);
    return ok;
}

/* ---- сеть ---- */
static long long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int write_all(int fd, const char *b, size_t n) {
    while (n) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        b += w; n -= (size_t)w;
    }
    return 0;
}

static void reply(int fd, const char *status) {
    char b[160];
    int n = snprintf(b, sizeof b, "HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status);
    if (n > 0) (void)write_all(fd, b, (size_t)n);
}

static int connect_timeout(const struct sockaddr *sa, socklen_t sl, int ms) {
    int fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    if (connect(fd, sa, sl) != 0) {
        if (errno != EINPROGRESS) { close(fd); return -1; }
        struct pollfd p = { fd, POLLOUT, 0 };
        int err = 0; socklen_t el = sizeof err;
        if (poll(&p, 1, ms) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            close(fd); return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);
    return fd;
}

/* К имени из списка — по первому публичному адресу, который ответил. */
static int dial(const char *host, unsigned port) {
    char ps[8]; snprintf(ps, sizeof ps, "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next)
        if (addr_public(a->ai_addr)) fd = connect_timeout(a->ai_addr, a->ai_addrlen, CONNECT_TIMEOUT_MS);
    freeaddrinfo(res);
    return fd;
}

/* Сквозная перекачка до закрытия обеих сторон или простоя. */
static void relay(int a, int b, unsigned long long *up, unsigned long long *down) {
    char buf[RELAY_BUF];
    int a_open = 1, b_open = 1;
    while (a_open || b_open) {
        struct pollfd p[2] = { { a, a_open ? POLLIN : 0, 0 }, { b, b_open ? POLLIN : 0, 0 } };
        int n = poll(p, 2, IDLE_TIMEOUT_MS);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return; }
        for (int i = 0; i < 2; i++) {
            int from = i ? b : a, to = i ? a : b;
            int *open = i ? &b_open : &a_open;
            if (!*open || !(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t r = recv(from, buf, sizeof buf, 0);
            if (r > 0) {
                if (write_all(to, buf, (size_t)r) != 0) return;
                if (i) *down += (unsigned long long)r; else *up += (unsigned long long)r;
            } else if (r == 0 || errno != EINTR) {
                *open = 0;
                shutdown(to, SHUT_WR);
            }
        }
    }
}

static atomic_int active;
static rate_limit limiter = { .mu = PTHREAD_MUTEX_INITIALIZER };

typedef struct { int fd; struct sockaddr_in peer; } conn_arg;

static void *serve(void *vp) {
    conn_arg *c = vp;
    int fd = c->fd;
    char peer[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &c->peer.sin_addr, peer, sizeof peer);
    free(c);
    long long t0 = now_ms();
    struct timeval tv = { HEAD_TIMEOUT_MS / 1000, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char head[HEAD_MAX];
    size_t got = 0;
    gate_req r;
    int pr = -1;
    while (got < sizeof head) {
        ssize_t n = recv(fd, head + got, sizeof head - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
        if ((pr = parse_head(head, got, &r)) != -1) break;
    }
    const char *result = "bad";
    unsigned long long up = 0, down = 0;
    if (pr != 0) {
        if (got) reply(fd, "400 Bad Request");
    } else if (!request_allowed(&r)) {
        reply(fd, "403 Forbidden");
        result = "forbidden";
    } else {
        int u = dial(r.host, r.port);
        if (u < 0) {
            reply(fd, "502 Bad Gateway");
            result = "unreachable";
        } else {
            struct timeval none = { 0, 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof none);
            int one = 1;
            setsockopt(u, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            int ok = 1;
            if (r.kind == REQ_CONNECT) {
                static const char est[] = "HTTP/1.1 200 Connection established\r\n\r\n";
                ok = write_all(fd, est, sizeof est - 1) == 0;
            } else {
                char req[HEAD_MAX + PATH_MAX_LEN + 512];
                long rn = build_origin_request(&r, head, req, sizeof req);
                ok = rn > 0 && write_all(u, req, (size_t)rn) == 0;
                if (!ok && rn <= 0) reply(fd, "400 Bad Request");
            }
            /* Байты, пришедшие вслед за заголовком (начало TLS после CONNECT),
               принадлежат сквозному потоку. */
            if (ok && got > r.head_len)
                ok = write_all(u, head + r.head_len, got - r.head_len) == 0;
            if (ok) {
                up += got > r.head_len ? got - r.head_len : 0;
                relay(fd, u, &up, &down);
                result = "ok";
            }
            close(u);
        }
    }
    fprintf(stderr, "d2k-gate: %s %s %s:%u — %s, к серверу %llu, к клиенту %llu, %lld мс\n",
            peer, pr == 0 ? r.method : "-", pr == 0 ? r.host : "-", pr == 0 ? r.port : 0,
            result, up, down, now_ms() - t0);
    close(fd);
    atomic_fetch_sub(&active, 1);
    return NULL;
}

int main(int argc, char **argv) {
    unsigned port = GATE_PORT;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) port = (unsigned)atoi(argv[++i]);
        else { fprintf(stderr, "usage: d2k-gate [--port N]\n"); return 2; }
    }
    signal(SIGPIPE, SIG_IGN);
    int lfd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port); a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (lfd < 0 || setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 128) != 0) {
        perror("d2k-gate: listen"); return 1;
    }
    fprintf(stderr, "d2k-gate: порт %u, имён в списке %zu\n", port,
            sizeof allowed_hosts / sizeof allowed_hosts[0] - 1);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);
    for (;;) {
        struct sockaddr_in peer; socklen_t pl = sizeof peer;
        int fd = accept(lfd, (struct sockaddr *)&peer, &pl);
        if (fd < 0) { if (errno == EINTR || errno == ECONNABORTED) continue; perror("d2k-gate: accept"); sleep(1); continue; }
        if (atomic_load(&active) >= CONN_MAX ||
            !rate_allow(&limiter, ntohl(peer.sin_addr.s_addr), time(NULL))) {
            reply(fd, "503 Service Unavailable");
            close(fd);
            continue;
        }
        conn_arg *c = malloc(sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd; c->peer = peer;
        atomic_fetch_add(&active, 1);
        pthread_t th;
        if (pthread_create(&th, &attr, serve, c) != 0) {
            atomic_fetch_sub(&active, 1);
            free(c); close(fd);
        }
    }
}
