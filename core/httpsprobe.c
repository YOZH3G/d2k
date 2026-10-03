/* httpsprobe.c — есть ли у имени HTTPS (задача 51), см. d2k_httpsprobe.h. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_hello.h"
#include "d2k_httpsprobe.h"
#include "d2k_tls12.h"
#include "d2k_tls13.h"

/* Отказ 443 приходит за один RTT; потолок ограничивает молчащую линию, а
   кэш избавляет от неё следующие запросы. */
#define CONNECT_MS 1500
#define PROBE_MS   2500
/* Сколько ждать первого байта ответа на ClientHello. Сервер отвечает за
   один RTT; тишина дольше — так коробка «роняет» поток. */
#define FIRST_MS   2000

uint16_t d2k_https_probe_port = 443;

d2k_https_state d2k_https_classify(int connect_result, int server_tls, int tls_ok, int peer_name) {
    if (connect_result == D2K_HTTPS_REFUSED) { return D2K_HTTPS_CLOSED; }
    if (connect_result != D2K_HTTPS_CONNECTED) { return D2K_HTTPS_UNCONFIRMED; }
    if (!server_tls) { return D2K_HTTPS_TLS_BLOCKED; }
    if (!tls_ok) { return D2K_HTTPS_UNCONFIRMED; }
    if (peer_name == 1) { return D2K_HTTPS_SERVED; }
    if (peer_name == 0) { return D2K_HTTPS_OTHER_NAME; }
    return D2K_HTTPS_UNCONFIRMED;
}

int d2k_https_upgrade(d2k_https_state s) {
    return s == D2K_HTTPS_SERVED || s == D2K_HTTPS_TLS_BLOCKED;
}

uint32_t d2k_https_ttl(d2k_https_state s) {
    switch (s) {
    case D2K_HTTPS_SERVED:      return 6u * 3600u;
    case D2K_HTTPS_TLS_BLOCKED: return 3600u;
    case D2K_HTTPS_CLOSED:      return 30u * 60u;
    case D2K_HTTPS_OTHER_NAME:  return 30u * 60u;
    case D2K_HTTPS_UNCONFIRMED: return 2u * 60u;
    default:                    return 0;
    }
}

const char *d2k_https_state_name(d2k_https_state s) {
    switch (s) {
    case D2K_HTTPS_SERVED:      return "served";
    case D2K_HTTPS_CLOSED:      return "closed";
    case D2K_HTTPS_OTHER_NAME:  return "other-name";
    case D2K_HTTPS_UNCONFIRMED: return "unconfirmed";
    case D2K_HTTPS_PROBING:     return "probing";
    case D2K_HTTPS_TLS_BLOCKED: return "tls-blocked";
    default:                    return "unknown";
    }
}

static int64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* --- настоящий зонд ------------------------------------------------------- */

static int https_connect(uint8_t family, const uint8_t *addr, uint32_t mark, int ms,
                         int *fd_out, char *why, size_t cap) {
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    if (family == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(d2k_https_probe_port);
        memcpy(&a->sin6_addr, addr, 16);
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(d2k_https_probe_port);
        memcpy(&a->sin_addr, addr, 4);
        sl = sizeof *a;
    }
    *fd_out = -1;
    int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(why, cap, "socket: %s", strerror(errno)); return D2K_HTTPS_NO_ANSWER; }
#ifdef SO_MARK
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark) != 0) {
        snprintf(why, cap, "SO_MARK: %s", strerror(errno));
        close(fd);
        return D2K_HTTPS_NO_ANSWER;
    }
#else
    (void)mark;
#endif
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(why, cap, "fcntl: %s", strerror(errno));
        close(fd);
        return D2K_HTTPS_NO_ANSWER;
    }
    int error = 0;
    if (connect(fd, (const struct sockaddr *)&ss, sl) != 0) {
        if (errno != EINPROGRESS) {
            error = errno;
        } else {
            struct pollfd p = {fd, POLLOUT, 0};
            int rc;
            do { rc = poll(&p, 1, ms); } while (rc < 0 && errno == EINTR);
            if (rc == 0) {
                snprintf(why, cap, "443 молчит %d мс", ms);
                close(fd);
                return D2K_HTTPS_NO_ANSWER;
            }
            socklen_t el = sizeof error;
            if (rc < 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &el) != 0) {
                error = errno ? errno : EIO;
            }
        }
    }
    if (error) {
        snprintf(why, cap, "443: %s", strerror(error));
        close(fd);
        return error == ECONNREFUSED || error == EHOSTUNREACH || error == ENETUNREACH
            ? D2K_HTTPS_REFUSED : D2K_HTTPS_NO_ANSWER;
    }
    if (fcntl(fd, F_SETFL, flags) < 0) {
        snprintf(why, cap, "fcntl: %s", strerror(errno));
        close(fd);
        return D2K_HTTPS_NO_ANSWER;
    }
    *fd_out = fd;
    return D2K_HTTPS_CONNECTED;
}

/* 1 — рукопожатие завершилось; *peer_name — как d2k_tls_peer_name. */
static int https_tls(int fd, const char *host, int ms, int v13, int *peer_name,
                     char *why, size_t cap) {
    *peer_name = -1;
    if (v13) {
        d2k_tls *t = NULL;
        if (d2k_tls_connect(fd, host, ms, 0, &t, why, cap) != 0) { return 0; }
        *peer_name = d2k_tls_peer_name(t);
        d2k_tls_free(t);
    } else {
        d2k_tls12 *t = NULL;
        if (d2k_tls12_connect(fd, host, ms, 0, &t, why, cap) != 0) { return 0; }
        *peer_name = d2k_tls12_peer_name(t);
        d2k_tls12_free(t);
    }
    snprintf(why, cap, "TLS 1.%d, имя в листе сертификата (цепочка не проверяется) %s", v13 ? 3 : 2,
             *peer_name == 1 ? "совпало" : *peer_name == 0 ? "чужое" : "не прочитано");
    return 1;
}

/* Первый полёт: наш ClientHello (профиль браузера, SNI = имя) и первый байт
   ответа. 1 — пришла запись TLS (рукопожатие или тревога) от сервера; 0 —
   сброс, закрытие, тишина FIRST_MS или не-TLS байты. Отдельным соединением:
   клиентам TLS d2k нечем сказать, пришло ли от сервера хоть что-то. */
static int first_flight(int fd, const char *host, char *why, size_t cap) {
    uint8_t hello[2048];
    size_t hl = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, host, hello, sizeof hello, &hl) != 0) {
        snprintf(why, cap, "ClientHello не собрался");
        return -1;
    }
    if (send(fd, hello, hl, 0) != (ssize_t)hl) {
        snprintf(why, cap, "443 принял, ClientHello не ушёл: %s", strerror(errno));
        return 0;
    }
    struct pollfd p = {fd, POLLIN, 0};
    int rc;
    do { rc = poll(&p, 1, FIRST_MS); } while (rc < 0 && errno == EINTR);
    /* Ошибка poll — «ответа нет», а не повод читать: блокирующий recv на
       молчащем соединении остановил бы единственный поток зонда (ревью N5). */
    if (rc <= 0) {
        snprintf(why, cap, "443 принял, на ClientHello тишина %d мс", FIRST_MS);
        return 0;
    }
    uint8_t b[2];
    ssize_t n = recv(fd, b, sizeof b, 0);
    if (n <= 0) {
        snprintf(why, cap, "443 принял, на ClientHello %s",
                 n == 0 ? "закрытие" : strerror(errno));
        return 0;
    }
    if ((b[0] == 0x16 || b[0] == 0x15) && (n < 2 || b[1] == 0x03)) { return 1; }
    snprintf(why, cap, "443 принял, на ClientHello не-TLS байты (0x%02x)", b[0]);
    return 0;
}

d2k_https_state d2k_https_probe_real(uint8_t family, const uint8_t *addr, const char *host,
                                     uint32_t mark, char *why, size_t cap) {
    why[0] = '\0';
    int fd;
    int cr0 = https_connect(family, addr, mark, CONNECT_MS, &fd, why, cap);
    if (cr0 != D2K_HTTPS_CONNECTED) { return d2k_https_classify(cr0, 0, 0, -1); }
    int ff = first_flight(fd, host, why, cap);
    close(fd);
    if (ff < 0) { return D2K_HTTPS_UNCONFIRMED; }
    if (ff == 0) { return d2k_https_classify(D2K_HTTPS_CONNECTED, 0, 0, -1); }

    /* Сервер говорит TLS: теперь полное рукопожатие — чьё имя в листе. */
    int64_t deadline = mono_ms() + PROBE_MS;
    int peer_name = -1, tls_ok = 0, cr = D2K_HTTPS_NO_ANSWER, tries = 0;
    char first[160] = "";
    why[0] = '\0';
    /* TLS 1.3 сначала; сервер, с которым наш единственный набор 1.3 не
       договорится, получает 1.2. */
    for (int v13 = 1; v13 >= 0 && !tls_ok; v13--) {
        int64_t left = deadline - mono_ms();
        if (left < 200) { break; }
        int fd;
        cr = https_connect(family, addr, mark, (int)(left < CONNECT_MS ? left : CONNECT_MS),
                           &fd, why, cap);
        if (cr != D2K_HTTPS_CONNECTED) { break; }
        left = deadline - mono_ms();
        tries++;
        tls_ok = left > 0 && https_tls(fd, host, (int)left, v13, &peer_name, why, cap);
        close(fd);
        if (!tls_ok && v13) { snprintf(first, sizeof first, "%s", why); }
    }
    if (!tls_ok && tries == 2) {
        char second[160];
        snprintf(second, sizeof second, "%s", why);
        snprintf(why, cap, "TLS 1.3: %s; TLS 1.2: %s", first, second);
    }
    /* Сервер уже ответил TLS первым полётом: повторный отказ соединения —
       не «HTTPS нет», а случай на линии. */
    if (cr != D2K_HTTPS_CONNECTED) { cr = D2K_HTTPS_NO_ANSWER; }
    return d2k_https_classify(cr, 1, tls_ok, peer_name);
}

/* --- кэш, очередь и поток ------------------------------------------------- */

typedef struct {
    char host[256];
    d2k_https_state state;
    int64_t expires_ms, stamp_ms;
} entry;

typedef struct {
    char host[256];
    uint8_t family, addr[16];
} job;

struct d2k_httpsprobe {
    uint32_t mark;
    d2k_https_probe_fn probe;
    entry cache[D2K_HTTPSPROBE_NAMES];
    pthread_mutex_t mu;
    pthread_cond_t cv;
    pthread_t th;
    int th_live, stop;
    job jobs[D2K_HTTPSPROBE_JOBS];
    size_t j_head, j_count;
    d2k_httpsprobe_result done[D2K_HTTPSPROBE_JOBS + 1];
    size_t d_count;
    uint64_t lost;
    int wake[2];
};

static int host_ok(const char *h) {
    size_t n = h ? strlen(h) : 0;
    if (n == 0 || n > 253) { return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.')) { return 0; }
    }
    return 1;
}

static entry *cache_find(d2k_httpsprobe *p, const char *host) {
    for (size_t i = 0; i < D2K_HTTPSPROBE_NAMES; i++) {
        if (p->cache[i].host[0] && strcasecmp(p->cache[i].host, host) == 0) { return &p->cache[i]; }
    }
    return NULL;
}

static entry *cache_put(d2k_httpsprobe *p, const char *host, d2k_https_state s,
                        int64_t expires, int64_t now) {
    entry *e = cache_find(p, host);
    if (!e) {
        /* Вытесняется самая давняя запись, но не та, по которой идёт зонд:
           иначе по имени ушёл бы второй (ревью M5). */
        e = NULL;
        for (size_t i = 0; i < D2K_HTTPSPROBE_NAMES; i++) {
            entry *c = &p->cache[i];
            if (!c->host[0]) { e = c; break; }
            if (c->state == D2K_HTTPS_PROBING && now < c->expires_ms) { continue; }
            if (!e || c->stamp_ms < e->stamp_ms) { e = c; }
        }
        if (!e) { e = &p->cache[0]; }
        snprintf(e->host, sizeof e->host, "%s", host);
    }
    e->state = s;
    e->stamp_ms = now;
    e->expires_ms = expires;
    return e;
}

static void *worker(void *arg) {
    d2k_httpsprobe *p = arg;
    pthread_mutex_lock(&p->mu);
    for (;;) {
        while (!p->stop && p->j_count == 0) { pthread_cond_wait(&p->cv, &p->mu); }
        if (p->stop) { break; }
        job j = p->jobs[p->j_head];
        p->j_head = (p->j_head + 1) % D2K_HTTPSPROBE_JOBS;
        p->j_count--;
        pthread_mutex_unlock(&p->mu);

        d2k_httpsprobe_result r;
        memset(&r, 0, sizeof r);
        snprintf(r.host, sizeof r.host, "%s", j.host);
        r.family = j.family;
        memcpy(r.addr, j.addr, sizeof r.addr);
        r.state = p->probe(j.family, j.addr, j.host, p->mark, r.why, sizeof r.why);
        if (r.state == D2K_HTTPS_UNKNOWN || r.state == D2K_HTTPS_PROBING) {
            r.state = D2K_HTTPS_UNCONFIRMED;
        }
        r.ttl_s = d2k_https_ttl(r.state);

        pthread_mutex_lock(&p->mu);
        if (p->d_count < sizeof p->done / sizeof p->done[0]) {
            p->done[p->d_count++] = r;
        } else {
            p->lost++;   /* имя перепроверится, когда истечёт PROBING */
        }
        if (p->wake[1] >= 0) {
            ssize_t w = write(p->wake[1], "x", 1);
            (void)w;
        }
    }
    pthread_mutex_unlock(&p->mu);
    return NULL;
}

d2k_httpsprobe *d2k_httpsprobe_new(uint32_t mark, d2k_https_probe_fn probe) {
    d2k_httpsprobe *p = calloc(1, sizeof *p);
    if (!p) { return NULL; }
    p->mark = mark;
    p->probe = probe ? probe : d2k_https_probe_real;
    p->wake[0] = p->wake[1] = -1;
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);
    if (pipe(p->wake) != 0) {
        p->wake[0] = p->wake[1] = -1;
    } else {
        for (int i = 0; i < 2; i++) {
            int fl = fcntl(p->wake[i], F_GETFL, 0);
            if (fl >= 0) { (void)fcntl(p->wake[i], F_SETFL, fl | O_NONBLOCK); }
        }
    }
    if (pthread_create(&p->th, NULL, worker, p) == 0) { p->th_live = 1; }
    if (!p->th_live || p->wake[0] < 0) {
        d2k_httpsprobe_free(p);
        return NULL;
    }
    return p;
}

void d2k_httpsprobe_free(d2k_httpsprobe *p) {
    if (!p) { return; }
    if (p->th_live) {
        pthread_mutex_lock(&p->mu);
        p->stop = 1;
        pthread_cond_broadcast(&p->cv);
        pthread_mutex_unlock(&p->mu);
        pthread_join(p->th, NULL);
    }
    if (p->wake[0] >= 0) { close(p->wake[0]); }
    if (p->wake[1] >= 0) { close(p->wake[1]); }
    pthread_cond_destroy(&p->cv);
    pthread_mutex_destroy(&p->mu);
    free(p);
}

int d2k_httpsprobe_wake_fd(const d2k_httpsprobe *p) {
    return p ? p->wake[0] : -1;
}

int d2k_httpsprobe_portal(d2k_httpsprobe *p, const char *host, uint8_t family,
                          const uint8_t *addr, int answered, int64_t now,
                          uint32_t *resend_ttl) {
    if (resend_ttl) { *resend_ttl = 0; }
    if (!p || !addr || (family != 4 && family != 6) || !host_ok(host)) { return 0; }
    pthread_mutex_lock(&p->mu);
    entry *e = cache_find(p, host);
    int rc = 0;
    if (e && now < e->expires_ms) {
        if (d2k_https_upgrade(e->state) && !answered && resend_ttl) {
            /* Датапат о подтверждённом имени не знает: перезапуск или вытеснение. */
            int64_t left = (e->expires_ms - now) / 1000;
            if (left > 0) {
                *resend_ttl = (uint32_t)left;
                rc = 2;
            }
        }
    } else if (p->j_count < D2K_HTTPSPROBE_JOBS) {
        job *j = &p->jobs[(p->j_head + p->j_count) % D2K_HTTPSPROBE_JOBS];
        memset(j, 0, sizeof *j);
        snprintf(j->host, sizeof j->host, "%s", host);
        j->family = family;
        memcpy(j->addr, addr, family == 6 ? 16 : 4);
        p->j_count++;
        /* Пока зонд идёт, по имени новых не ставим; срок с запасом на зонд. */
        cache_put(p, host, D2K_HTTPS_PROBING, now + PROBE_MS * 4, now);
        pthread_cond_signal(&p->cv);
        rc = 1;
    }
    pthread_mutex_unlock(&p->mu);
    return rc;
}

size_t d2k_httpsprobe_done(d2k_httpsprobe *p, int64_t now, d2k_httpsprobe_result *out,
                           size_t cap) {
    if (!p || !out) { return 0; }
    char drain[64];
    while (read(p->wake[0], drain, sizeof drain) > 0) { }
    pthread_mutex_lock(&p->mu);
    size_t n = p->d_count < cap ? p->d_count : cap;
    for (size_t i = 0; i < n; i++) {
        out[i] = p->done[i];
        cache_put(p, out[i].host, out[i].state, now + (int64_t)out[i].ttl_s * 1000, now);
    }
    memmove(p->done, p->done + n, (p->d_count - n) * sizeof p->done[0]);
    p->d_count -= n;
    if (p->d_count && p->wake[1] >= 0) {
        ssize_t w = write(p->wake[1], "x", 1);
        (void)w;
    }
    pthread_mutex_unlock(&p->mu);
    return n;
}

d2k_https_state d2k_httpsprobe_state(d2k_httpsprobe *p, const char *host, int64_t now) {
    if (!p || !host) { return D2K_HTTPS_UNKNOWN; }
    pthread_mutex_lock(&p->mu);
    entry *e = cache_find(p, host);
    d2k_https_state s = e && now < e->expires_ms ? e->state : D2K_HTTPS_UNKNOWN;
    pthread_mutex_unlock(&p->mu);
    return s;
}

uint64_t d2k_httpsprobe_lost(d2k_httpsprobe *p) {
    if (!p) { return 0; }
    pthread_mutex_lock(&p->mu);
    uint64_t n = p->lost;
    pthread_mutex_unlock(&p->mu);
    return n;
}

/* --- кэш на диске (ревью I2) ------------------------------------------------ */

static const struct { d2k_https_state s; const char *name; } stored[] = {
    {D2K_HTTPS_SERVED, "served"}, {D2K_HTTPS_TLS_BLOCKED, "tls-blocked"},
    {D2K_HTTPS_CLOSED, "closed"}, {D2K_HTTPS_OTHER_NAME, "other-name"},
    {D2K_HTTPS_UNCONFIRMED, "unconfirmed"},
};

int d2k_httpsprobe_save(d2k_httpsprobe *p, const char *path, int64_t now_ms, int64_t wall_s,
                        char *err, size_t cap) {
    if (!p || !path) { return -1; }
    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        snprintf(err, cap, "путь длиннее %zu", sizeof tmp);
        return -1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) { snprintf(err, cap, "%s: %s", tmp, strerror(errno)); return -1; }
    /* v2: отметка записи по стенным часам (ревью N2). */
    fprintf(f, "d2k-https 2 %lld\n", (long long)wall_s);
    pthread_mutex_lock(&p->mu);
    for (size_t i = 0; i < D2K_HTTPSPROBE_NAMES; i++) {
        const entry *e = &p->cache[i];
        if (!e->host[0] || e->state == D2K_HTTPS_PROBING || e->expires_ms <= now_ms) { continue; }
        const char *name = d2k_https_state_name(e->state);
        fprintf(f, "%s %lld %s\n", name,
                (long long)(wall_s + (e->expires_ms - now_ms) / 1000), e->host);
    }
    pthread_mutex_unlock(&p->mu);
    int bad = fflush(f) != 0 || fsync(fileno(f)) != 0;
    bad |= fclose(f) != 0;
    if (bad || rename(tmp, path) != 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

int d2k_httpsprobe_load(d2k_httpsprobe *p, const char *path, int64_t now_ms, int64_t wall_s,
                        d2k_httpsprobe_result *push, size_t push_cap, size_t *n_push,
                        size_t *n_loaded, char *err, size_t cap) {
    if (n_push) { *n_push = 0; }
    if (n_loaded) { *n_loaded = 0; }
    if (!p || !path) { return -1; }
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) { return 0; }
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        return -1;
    }
    char line[512];
    long long written = -1;
    int used = 0;
    if (!fgets(line, sizeof line, f) ||
        (strcmp(line, "d2k-https 1\n") != 0 &&
         (sscanf(line, "d2k-https 2 %lld\n%n", &written, &used) != 1 || line[used] != '\0' ||
          written < 0))) {
        fclose(f);
        snprintf(err, cap, "%s: не кэш HTTPS d2k (нет заголовка «d2k-https 1|2»)", path);
        return -1;
    }
    if (written > wall_s) {
        /* Файл записан позже, чем «сейчас»: часы отстают (Keenetic без RTC
           до NTP). Сколько знанию на самом деле — не узнать; не оживляем. */
        fclose(f);
        return 0;
    }
    while (fgets(line, sizeof line, f)) {
        char st[32], host[300];
        long long exp;
        used = 0;
        if (sscanf(line, "%31s %lld %299s %n", st, &exp, host, &used) != 3 ||
            line[used] != '\0' || !host_ok(host)) { continue; }
        d2k_https_state s = D2K_HTTPS_UNKNOWN;
        for (size_t i = 0; i < sizeof stored / sizeof stored[0]; i++) {
            if (strcmp(st, stored[i].name) == 0) { s = stored[i].s; }
        }
        if (s == D2K_HTTPS_UNKNOWN || exp <= wall_s) { continue; }
        int64_t left = exp - wall_s;
        if (left > (int64_t)d2k_https_ttl(s)) { left = d2k_https_ttl(s); }
        pthread_mutex_lock(&p->mu);
        cache_put(p, host, s, now_ms + left * 1000, now_ms);
        pthread_mutex_unlock(&p->mu);
        if (n_loaded) { (*n_loaded)++; }
        if (d2k_https_upgrade(s) && push && n_push && *n_push < push_cap) {
            d2k_httpsprobe_result *r = &push[(*n_push)++];
            memset(r, 0, sizeof *r);
            snprintf(r->host, sizeof r->host, "%.253s", host);
            r->state = s;
            r->ttl_s = (uint32_t)left;
            snprintf(r->why, sizeof r->why, "из кэша на диске");
        }
    }
    fclose(f);
    return 0;
}
