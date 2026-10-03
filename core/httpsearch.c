/* httpsearch.c — поиск обхода открытого HTTP (задача 51, шаг 4), см.
 * d2k_httpsearch.h. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_httpsearch.h"
#include "d2k_httpup.h"

uint16_t d2k_hs_probe_port = 80;
int d2k_hs_probe_ms = 6000;

/* Приманка — то же имя, что у TLS-поиска (SCHED_DECOY, core/sched.c):
   заведомо не связанное с целью и реально обслуживаемое. */
#define HS_DECOY "disk.rzd.ru"
/* Сколько ждать подтверждения датапата и события APPLIED после ответа. */
#define HS_ACK_MS     3000
#define HS_APPLIED_MS 500
/* Подтверждение — два настоящих ответа подряд одним кандидатом. */
#define HS_CONFIRM    2

static int64_t mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

const char *d2k_hs_answer_name(d2k_hs_answer a) {
    switch (a) {
    case D2K_HS_REAL:         return "ответ сервера";
    case D2K_HS_INJECTED:     return "вставка провайдера";
    case D2K_HS_EARLY:        return "ответ раньше RTT/2 (не сервер)";
    case D2K_HS_GARBAGE:      return "не ответ HTTP";
    case D2K_HS_SILENT:       return "тишина";
    case D2K_HS_RESET:        return "сброс";
    case D2K_HS_CLOSED:       return "закрытие без ответа";
    case D2K_HS_CONNECT_FAIL: return "соединение не установилось";
    case D2K_HS_DECOY:        return "ответ на приманку, не на запрос цели";
    default:                  return "нет";
    }
}

/* --- суждение ---------------------------------------------------------------- */

d2k_hs_answer d2k_hs_judge(const char *host, const char *head, size_t n,
                           int64_t rtt_us, int64_t reply_us) {
    if (!head || n < 12 || memcmp(head, "HTTP/1.", 7) != 0 ||
        (head[7] != '0' && head[7] != '1') || head[8] != ' ' ||
        head[9] < '1' || head[9] > '5' || head[10] < '0' || head[10] > '9' ||
        head[11] < '0' || head[11] > '9') {
        return D2K_HS_GARBAGE;
    }
    char portal[256];
    if (host && d2k_httpup_portal_location(host, head, n, portal, sizeof portal)) {
        return D2K_HS_INJECTED;
    }
    /* ПРИМАНКА ДОШЛА ДО СЕРВЕРА (повторное ревью I-A): сервер принял её
       байты за начало запроса и ответил на склейку — 400/421 или ответ про
       имя приманки. Это не ответ цели, и подтверждать по нему план нельзя:
       такой план отдавал бы серверу приманку вместо каждого запроса. */
    int code = (head[9] - '0') * 100 + (head[10] - '0') * 10 + (head[11] - '0');
    if (code == 400 || code == 421) { return D2K_HS_DECOY; }
    {
        static const char decoy[] = HS_DECOY;
        const size_t dl = sizeof decoy - 1;
        for (size_t i = 0; i + dl <= n; i++) {
            if (!strncasecmp(head + i, decoy, dl)) { return D2K_HS_DECOY; }
        }
    }
    /* То же правило, что у датапата (http80.c): сервер не может ответить
       раньше, чем запрос дошёл до него и вернулся. */
    if (rtt_us > 0 && reply_us >= 0 && reply_us * 2 < rtt_us) {
        return D2K_HS_EARLY;
    }
    return D2K_HS_REAL;
}

/* --- зонд -------------------------------------------------------------------- */

void d2k_hs_probe_run(const d2k_hs_job *job, d2k_hs_result *r) {
    memset(r, 0, sizeof *r);
    r->answer = D2K_HS_CONNECT_FAIL;
    r->fd = job ? job->fd : -1;
    r->seq = job ? job->seq : 0;
    if (!job || job->fd < 0) { snprintf(r->why, sizeof r->why, "нет сокета"); return; }
    int fd = job->fd;
    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof ss);
    if (job->family == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(d2k_hs_probe_port);
        memcpy(&a->sin6_addr, job->addr, 16);
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(d2k_hs_probe_port);
        memcpy(&a->sin_addr, job->addr, 4);
        sl = sizeof *a;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(r->why, sizeof r->why, "fcntl: %s", strerror(errno));
        return;
    }
    int64_t t0 = mono_ms(), deadline = t0 + d2k_hs_probe_ms;
    struct timespec c0, c1;
    clock_gettime(CLOCK_MONOTONIC, &c0);
    int err = 0;
    if (connect(fd, (const struct sockaddr *)&ss, sl) != 0) {
        if (errno != EINPROGRESS) {
            err = errno;
        } else {
            struct pollfd p = {fd, POLLOUT, 0};
            int rc;
            do { rc = poll(&p, 1, (int)(deadline - mono_ms())); } while (rc < 0 && errno == EINTR);
            if (rc <= 0) {
                snprintf(r->why, sizeof r->why, "80 молчит %d мс", d2k_hs_probe_ms);
                return;
            }
            socklen_t el = sizeof err;
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) { err = errno ? errno : EIO; }
        }
    }
    if (err) {
        snprintf(r->why, sizeof r->why, "80: %s", strerror(err));
        return;
    }
    clock_gettime(CLOCK_MONOTONIC, &c1);
    r->rtt_us = (int64_t)(c1.tv_sec - c0.tv_sec) * 1000000 + (c1.tv_nsec - c0.tv_nsec) / 1000;

    char req[512];
    int rl = snprintf(req, sizeof req,
                      "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n", job->host);
    if (rl <= 0 || (size_t)rl >= sizeof req) { r->answer = D2K_HS_GARBAGE; return; }
    struct timespec s0;
    clock_gettime(CLOCK_MONOTONIC, &s0);
    size_t sent = 0;
    while (sent < (size_t)rl) {
        ssize_t w = send(fd, req + sent, (size_t)rl - sent, 0);
        if (w > 0) { sent += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
            struct pollfd p = {fd, POLLOUT, 0};
            if (poll(&p, 1, (int)(deadline - mono_ms())) <= 0) { break; }
            continue;
        }
        break;
    }
    char head[4096];
    size_t n = 0;
    int first = 0;
    for (;;) {
        int64_t left = deadline - mono_ms();
        if (left <= 0) { break; }
        struct pollfd p = {fd, POLLIN, 0};
        int rc = poll(&p, 1, (int)left);
        if (rc < 0 && errno == EINTR) { continue; }
        if (rc <= 0) { break; }
        ssize_t got = recv(fd, head + n, sizeof head - 1 - n, 0);
        if (got < 0 && (errno == EAGAIN || errno == EINTR)) { continue; }
        if (got < 0) {
            if (!n) {
                r->answer = errno == ECONNRESET ? D2K_HS_RESET : D2K_HS_CLOSED;
                snprintf(r->why, sizeof r->why, "%s", strerror(errno));
                return;
            }
            break;
        }
        if (got == 0) {
            if (!n) { r->answer = D2K_HS_CLOSED; snprintf(r->why, sizeof r->why, "закрытие"); return; }
            break;
        }
        if (!first) {
            struct timespec f;
            clock_gettime(CLOCK_MONOTONIC, &f);
            r->reply_us = (int64_t)(f.tv_sec - s0.tv_sec) * 1000000 + (f.tv_nsec - s0.tv_nsec) / 1000;
            first = 1;
        }
        n += (size_t)got;
        head[n] = '\0';
        if (strstr(head, "\r\n\r\n") || n >= sizeof head - 1) { break; }
    }
    if (!n) {
        r->answer = D2K_HS_SILENT;
        snprintf(r->why, sizeof r->why, "ответа нет %d мс", d2k_hs_probe_ms);
        return;
    }
    head[n] = '\0';
    r->answer = d2k_hs_judge(job->host, head, n, r->rtt_us, r->reply_us);
    const char *eol = strstr(head, "\r\n");
    size_t sl2 = eol ? (size_t)(eol - head) : n;
    if (sl2 >= sizeof r->status) { sl2 = sizeof r->status - 1; }
    for (size_t i = 0; i < sl2; i++) {
        unsigned char c = (unsigned char)head[i];
        r->status[i] = (char)(c >= 0x20 && c < 0x7f ? c : '.');
    }
    r->status[sl2] = '\0';
}

/* --- кандидаты --------------------------------------------------------------- */

static const char *const CANDS[] = {"split", "disorder", "fake-badsum", "fake-seqshift"};
#define N_CANDS (sizeof CANDS / sizeof CANDS[0])

size_t d2k_hs_candidate_count(void) { return N_CANDS; }
const char *d2k_hs_candidate_key(size_t i) { return i < N_CANDS ? CANDS[i] : NULL; }

/* Ключ измеренной порчи: «fake:» + признаки через «+» в порядке ttl,
   badsum, seqshift. Пишет строку признаков для плана в spec (через пробел). */
static int poison_key_spec(const char *key, char *spec, size_t cap) {
    if (strncmp(key, "fake:", 5) != 0 || !key[5] || strlen(key) > 39) { return -1; }
    char buf[48];
    snprintf(buf, sizeof buf, "%s", key + 5);
    size_t pos = 0;
    int have_ttl = 0, have_bad = 0, have_seq = 0, order = 0;
    spec[0] = '\0';
    for (char *tok = strtok(buf, "+"); tok; tok = strtok(NULL, "+")) {
        int rank;
        char *end = NULL;
        if (!strcmp(tok, "badsum")) { if (have_bad++) return -1; rank = 2; }
        else if (!strncmp(tok, "ttl=", 4)) {
            long v = strtol(tok + 4, &end, 10);
            if (have_ttl++ || !tok[4] || *end || v < 1 || v > 255) return -1;
            rank = 1;
        } else if (!strncmp(tok, "seqshift=", 9)) {
            long v = strtol(tok + 9, &end, 10);
            if (have_seq++ || !tok[9] || *end || v < -2147483647L || v > 2147483647L || v == 0) return -1;
            rank = 3;
        } else { return -1; }
        if (rank <= order) { return -1; }   /* канонический порядок */
        order = rank;
        int k = snprintf(spec + pos, cap - pos, "%s%s", pos ? " " : "", tok);
        if (k < 0 || (size_t)k >= cap - pos) { return -1; }
        pos += (size_t)k;
    }
    /* ttl одна приманку до сервера не останавливает наверняка. */
    if (have_ttl && !have_bad && !have_seq) { return -1; }
    return pos ? 0 : -1;
}

static int known_key(const char *k) {
    for (size_t i = 0; i < N_CANDS; i++) { if (!strcmp(CANDS[i], k)) return 1; }
    char spec[64];
    return poison_key_spec(k, spec, sizeof spec) == 0;
}

int d2k_hs_candidate_text(const char *key, const uint8_t id[16], char *buf, size_t cap) {
    if (!key || !buf || !known_key(key)) { return -1; }
    char idhex[33];
    for (int i = 0; i < 16; i++) { snprintf(idhex + 2 * i, 3, "%02x", id ? id[i] : 0); }
    int n = snprintf(buf, cap, "d2k-plan 1 11\nid %s\nproto tcp http\n", idhex);
    if (n < 0 || (size_t)n >= cap) { return -1; }
    size_t pos = (size_t)n;
#define ADD(...) do { int k_ = snprintf(buf + pos, cap - pos, __VA_ARGS__); \
                      if (k_ < 0 || (size_t)k_ >= cap - pos) { return -1; } \
                      pos += (size_t)k_; } while (0)
    if (!strncmp(key, "fake-", 5) || !strncmp(key, "fake:", 5)) {
        static const char fake[] = "GET / HTTP/1.1\r\nHost: " HS_DECOY "\r\n\r\n";
        char spec[64];
        if (!strcmp(key, "fake-badsum")) { snprintf(spec, sizeof spec, "badsum"); }
        else if (!strcmp(key, "fake-seqshift")) { snprintf(spec, sizeof spec, "seqshift=-66000"); }
        else if (poison_key_spec(key, spec, sizeof spec) != 0) { return -1; }
        ADD("payload 1 ");
        for (size_t i = 0; i < sizeof fake - 1; i++) { ADD("%02x", (unsigned char)fake[i]); }
        ADD("\n");
        ADD("poison 1 %s\n", spec);
        ADD("fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n");
    }
    ADD("split sni_middle +0\n");
    if (!strcmp(key, "disorder")) {
        /* Та же пауза между кусками, что у вопроса порядка в TLS-поиске
           (D2K_PACE_PIECE_US, compose.h). */
        ADD("order reverse\npace 12000\n");
    }
#undef ADD
    return 0;
}

/* Постоянный план кандидата — свой устойчивый идентификатор. */
static void stable_id(const char *key, uint8_t id[16]) {
    uint64_t h = 1469598103934665603ull;
    for (const char *p = "d2k-http:"; *p; p++) { h = (h ^ (uint8_t)*p) * 1099511628211ull; }
    for (const char *p = key; *p; p++) { h = (h ^ (uint8_t)*p) * 1099511628211ull; }
    for (int i = 0; i < 16; i++) { h = (h ^ (uint64_t)i) * 1099511628211ull; id[i] = (uint8_t)(h >> 56); }
}

static void fresh_id(uint8_t id[16]) {
    static uint64_t ctr;
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd >= 0) {
        while (got < 16) {
            ssize_t r = read(fd, id + got, 16 - got);
            if (r > 0) { got += (size_t)r; continue; }
            if (r < 0 && errno == EINTR) { continue; }
            break;
        }
        close(fd);
    }
    if (got < 16) {
        uint64_t h = (uint64_t)mono_ms() ^ (++ctr * 0x9e3779b97f4a7c15ull);
        for (int i = 0; i < 16; i++) { h = h * 6364136223846793005ull + 1442695040888963407ull; id[i] = (uint8_t)(h >> 56); }
    }
    id[0] |= 1;   /* нулевой идентификатор — «нет идентичности» */
}

/* --- поиск ------------------------------------------------------------------- */

typedef struct {
    char host[256];
    uint8_t family;
    char key[40];          /* подтверждённый кандидат; "" — нет */
    uint64_t seq;          /* порядок подтверждения: свежие — первыми */
    int64_t no_before_ms;  /* раньше этого новый поиск/перепроверка не начинается */
    int64_t wall;          /* когда подтверждён (стенные часы, из файла) */
} rec;

typedef struct { char host[256]; uint8_t family, addr[16]; } pend;

enum { PH_IDLE = 0, PH_BASE, PH_ACK, PH_RUN, PH_APPLIED };

struct d2k_httpsearch {
    d2k_hs_ops ops;
    rec *recs; size_t n_recs, cap_recs;
    char measured[8][40]; size_t n_measured;   /* ключи измеренной порчи */
    uint32_t job_seq;
    pend *q; size_t n_q, cap_q;
    uint64_t seq;
    struct {
        int phase;
        char host[256];
        uint8_t family, addr[16];
        int recheck;
        char cands[N_CANDS * 4 + 8][40];
        size_t n_cands, idx;
        int ok;            /* настоящих ответов подряд у текущего кандидата */
        int judged;        /* судимых испытаний: ответ сервера или вставка под планом */
        uint32_t job_seq;  /* номер текущего запуска зонда */
        int fd;
        uint16_t sport;
        uint8_t trial[16], plan_id[16];
        int applied;
        int64_t deadline;
        d2k_hs_result pending;
    } cur;
};

static void say(d2k_httpsearch *hs, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(d2k_httpsearch *hs, const char *fmt, ...) {
    if (!hs->ops.say) { return; }
    char line[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    hs->ops.say(hs->ops.ctx, line);
}

static int host_ok(const char *h) {
    size_t n = h ? strlen(h) : 0;
    if (n == 0 || n > 253) { return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.')) { return 0; }
    }
    /* Адрес IPv4 — не имя (ревью M-2). */
    const char *last = strrchr(h, '.');
    last = last ? last + 1 : h;
    if (!*last) { return 0; }
    for (; *last; last++) { if (*last < '0' || *last > '9') { return 1; } }
    return 0;
}

static rec *rec_find(const d2k_httpsearch *hs, const char *host, uint8_t family) {
    for (size_t i = 0; i < hs->n_recs; i++) {
        if (hs->recs[i].family == family && !strcasecmp(hs->recs[i].host, host)) {
            return &hs->recs[i];
        }
    }
    return NULL;
}

static rec *rec_get(d2k_httpsearch *hs, const char *host, uint8_t family) {
    rec *r = rec_find(hs, host, family);
    if (r) { return r; }
    if (hs->n_recs == hs->cap_recs) {
        size_t nc = hs->cap_recs ? hs->cap_recs * 2 : 16;
        rec *nv = realloc(hs->recs, nc * sizeof *nv);
        if (!nv) { return NULL; }
        hs->recs = nv;
        hs->cap_recs = nc;
    }
    r = &hs->recs[hs->n_recs++];
    memset(r, 0, sizeof *r);
    snprintf(r->host, sizeof r->host, "%s", host);
    r->family = family;
    return r;
}

int d2k_httpsearch_measured_poison(d2k_httpsearch *hs, const char *spec) {
    if (!hs || !spec) { return -1; }
    /* Строка признаков → канонический ключ. */
    char buf[64], key[48] = "fake:";
    char ttl[16] = "", seq[24] = "";
    int bad = 0;
    snprintf(buf, sizeof buf, "%s", spec);
    for (char *tok = strtok(buf, " \t"); tok; tok = strtok(NULL, " \t")) {
        if (!strcmp(tok, "badsum")) { bad = 1; }
        else if (!strncmp(tok, "ttl=", 4) && strlen(tok) < sizeof ttl) { snprintf(ttl, sizeof ttl, "%s", tok); }
        else if (!strncmp(tok, "seqshift=", 9) && strlen(tok) < sizeof seq) { snprintf(seq, sizeof seq, "%s", tok); }
        else { return -1; }
    }
    size_t n = 5;
    if (ttl[0]) { n += (size_t)snprintf(key + n, sizeof key - n, "%s", ttl); }
    if (bad) { n += (size_t)snprintf(key + n, sizeof key - n, "%sbadsum", n > 5 ? "+" : ""); }
    if (seq[0]) { n += (size_t)snprintf(key + n, sizeof key - n, "%s%s", n > 5 ? "+" : "", seq); }
    if (n == 5 || n >= sizeof key) { return -1; }
    /* Та же порча, что у заготовки, — ключ заготовки (одно имя на одно). */
    const char *use = key;
    if (!strcmp(key, "fake:badsum")) { use = "fake-badsum"; }
    else if (!strcmp(key, "fake:seqshift=-66000")) { use = "fake-seqshift"; }
    else if (!known_key(key)) { return -1; }
    for (size_t i = 0; i < hs->n_measured; i++) { if (!strcmp(hs->measured[i], use)) return 0; }
    if (hs->n_measured >= sizeof hs->measured / sizeof hs->measured[0]) { return -1; }
    snprintf(hs->measured[hs->n_measured++], sizeof hs->measured[0], "%s", use);
    return 0;
}

size_t d2k_hs_plan_poisons(const char *text, char out[][64], size_t cap) {
    size_t n = 0;
    if (!text || !strstr(text, "\nproto tcp tls\n")) { return 0; }
    for (const char *ln = text; ln && *ln && n < cap;) {
        unsigned id = 0;
        int used = 0;
        if (sscanf(ln, "poison %u %n", &id, &used) == 1 && used) {
            char ref[32];
            snprintf(ref, sizeof ref, " poison=%u ", id);
            const char *e = strchr(ln + used, '\n');
            size_t len = e ? (size_t)(e - (ln + used)) : strlen(ln + used);
            /* Порча именно приманки («fake … poison=N»), не перекрытия. */
            const char *f = strstr(text, "\nfake ");
            int is_fake = 0;
            while (f) {
                const char *fe = strchr(f + 1, '\n');
                size_t fl = fe ? (size_t)(fe - f) : strlen(f);
                char line[256];
                if (fl < sizeof line) {
                    memcpy(line, f, fl); line[fl] = ' '; line[fl + 1 < sizeof line ? fl + 1 : fl] = '\0';
                    if (strstr(line, ref)) { is_fake = 1; break; }
                }
                f = strstr(f + 1, "\nfake ");
            }
            if (is_fake && len > 0 && len < 64) {
                memcpy(out[n], ln + used, len);
                out[n][len] = '\0';
                n++;
            }
        }
        const char *nl = strchr(ln, '\n');
        ln = nl ? nl + 1 : NULL;
    }
    return n;
}

d2k_httpsearch *d2k_httpsearch_new(const d2k_hs_ops *ops) {
    d2k_httpsearch *hs = calloc(1, sizeof *hs);
    if (!hs) { return NULL; }
    if (ops) { hs->ops = *ops; }
    hs->cur.fd = -1;
    return hs;
}

static void drop_socket(d2k_httpsearch *hs) {
    if (hs->cur.fd >= 0) {
        if (hs->ops.close_port) { hs->ops.close_port(hs->ops.ctx, hs->cur.fd); }
        hs->cur.fd = -1;
    }
}

static void drop_probe(d2k_httpsearch *hs) {
    if (hs->cur.sport && hs->ops.del_probe) {
        hs->ops.del_probe(hs->ops.ctx, hs->cur.host, hs->cur.family, hs->cur.sport);
    }
    hs->cur.sport = 0;
}

void d2k_httpsearch_free(d2k_httpsearch *hs) {
    if (!hs) { return; }
    if (hs->cur.phase == PH_ACK || hs->cur.phase == PH_RUN) { drop_probe(hs); }
    drop_socket(hs);
    free(hs->recs);
    free(hs->q);
    free(hs);
}

int d2k_httpsearch_busy(const d2k_httpsearch *hs) {
    return hs && hs->cur.phase != PH_IDLE;
}

const char *d2k_httpsearch_plan_of(const d2k_httpsearch *hs, const char *host, uint8_t family) {
    const rec *r = hs && host ? rec_find(hs, host, family) : NULL;
    return r && r->key[0] ? r->key : NULL;
}

static void start_next(d2k_httpsearch *hs, int64_t now);

static void finish(d2k_httpsearch *hs, int64_t now) {
    drop_socket(hs);
    hs->cur.phase = PH_IDLE;
    hs->cur.sport = 0;
    start_next(hs, now);
}

static int open_job(d2k_httpsearch *hs, d2k_hs_job *job) {
    memset(job, 0, sizeof *job);
    int fd = -1;
    uint16_t sport = 0;
    if (!hs->ops.open_port || hs->ops.open_port(hs->ops.ctx, hs->cur.family, &fd, &sport) != 0 ||
        fd < 0 || !sport) {
        return -1;
    }
    hs->cur.fd = fd;
    hs->cur.sport = sport;
    job->fd = fd;
    job->family = hs->cur.family;
    memcpy(job->addr, hs->cur.addr, sizeof job->addr);
    snprintf(job->host, sizeof job->host, "%s", hs->cur.host);
    return 0;
}

static void next_candidate(d2k_httpsearch *hs, int64_t now);

static void all_failed(d2k_httpsearch *hs, int64_t now) {
    rec *r = rec_get(hs, hs->cur.host, hs->cur.family);
    if (!hs->cur.judged) {
        /* Ни одного судимого испытания (ревью I-2): исполнение не
           подтвердилось, датапат отказал или не ответил. О коробке это
           ничего не говорит — план, если был, остаётся. */
        if (r) { r->no_before_ms = now + D2K_HS_INCONCLUSIVE_MS; }
        say(hs, "HTTP %s: поиск не измерен — ни один вопрос не дал исполненного опыта "
                "(нет APPLIED, отказ или молчание датапата)%s; повтор не раньше чем через "
                "%lld мин", hs->cur.host,
            r && r->key[0] ? ", подтверждённый план оставлен" : "",
            (long long)(D2K_HS_INCONCLUSIVE_MS / 60000));
        finish(hs, now);
        return;
    }
    if (r && r->key[0]) {
        /* Перепроверка не подтвердила ни прежний план, ни другой: снимаем
           только свой постоянный план этого имени и формы HTTP. */
        if (hs->ops.del_plan) { hs->ops.del_plan(hs->ops.ctx, r->host, r->family); }
        r->key[0] = '\0';
        if (hs->ops.changed) { hs->ops.changed(hs->ops.ctx); }
    }
    if (r) { r->no_before_ms = now + D2K_HS_RETRY_MS; }
    say(hs, "HTTP %s: обход не найден — ни один вопрос не дал ответа сервера; "
            "следующая попытка не раньше чем через %lld мин", hs->cur.host,
        (long long)(D2K_HS_RETRY_MS / 60000));
    finish(hs, now);
}

static void confirmed(d2k_httpsearch *hs, int64_t now) {
    const char *key = hs->cur.cands[hs->cur.idx];
    uint8_t id[16];
    char text[2048];
    stable_id(key, id);
    rec *r = rec_get(hs, hs->cur.host, hs->cur.family);
    if (d2k_hs_candidate_text(key, id, text, sizeof text) != 0 || !r ||
        !hs->ops.set_plan || hs->ops.set_plan(hs->ops.ctx, hs->cur.host, hs->cur.family, text) != 0) {
        say(hs, "HTTP %s: план «%s» подтверждён, но не поставлен датапату", hs->cur.host, key);
        finish(hs, now);
        return;
    }
    snprintf(r->key, sizeof r->key, "%s", key);
    r->seq = ++hs->seq;
    r->wall = 0;
    r->no_before_ms = now + D2K_HS_RECHECK_MS;
    if (hs->ops.changed) { hs->ops.changed(hs->ops.ctx); }
    say(hs, "HTTP %s: обход найден — «%s», %d настоящих ответа сервера подряд под пробным "
            "планом; поставлен постоянным (форма HTTP)", hs->cur.host, key, HS_CONFIRM);
    finish(hs, now);
}

static void judge_trial(d2k_httpsearch *hs, const d2k_hs_result *r, int64_t now) {
    const char *key = hs->cur.cands[hs->cur.idx];
    if (!hs->cur.applied) {
        say(hs, "HTTP %s: «%s» — план не исполнен на проводе (нет APPLIED), кандидат не судим",
            hs->cur.host, key);
        hs->cur.ok = 0;
        hs->cur.idx++;
        next_candidate(hs, now);
        return;
    }
    if (r->answer == D2K_HS_REAL || r->answer == D2K_HS_INJECTED) { hs->cur.judged++; }
    if (r->answer == D2K_HS_REAL) {
        hs->cur.ok++;
        say(hs, "HTTP %s: «%s» — ответ сервера (%s), RTT %lld мкс, ответ через %lld мкс",
            hs->cur.host, key, r->status, (long long)r->rtt_us, (long long)r->reply_us);
        if (hs->cur.ok >= HS_CONFIRM) { confirmed(hs, now); return; }
        next_candidate(hs, now);     /* тот же кандидат ещё раз */
        return;
    }
    say(hs, "HTTP %s: «%s» — %s%s%s", hs->cur.host, key, d2k_hs_answer_name(r->answer),
        r->why[0] ? ": " : "", r->why);
    hs->cur.ok = 0;
    hs->cur.idx++;
    next_candidate(hs, now);
}

static void next_candidate(d2k_httpsearch *hs, int64_t now) {
    drop_socket(hs);
    hs->cur.sport = 0;
    if (hs->cur.idx >= hs->cur.n_cands) { all_failed(hs, now); return; }
    const char *key = hs->cur.cands[hs->cur.idx];
    char text[2048];
    d2k_hs_job job;
    fresh_id(hs->cur.plan_id);
    fresh_id(hs->cur.trial);
    hs->cur.applied = 0;
    if (d2k_hs_candidate_text(key, hs->cur.plan_id, text, sizeof text) != 0 ||
        open_job(hs, &job) != 0) {
        say(hs, "HTTP %s: «%s» — сокет зонда не открылся, поиск остановлен", hs->cur.host, key);
        finish(hs, now);
        return;
    }
    if (!hs->ops.set_probe ||
        hs->ops.set_probe(hs->ops.ctx, hs->cur.host, hs->cur.family, hs->cur.sport,
                          text, hs->cur.trial) != 0) {
        say(hs, "HTTP %s: «%s» — пробный план не отправлен датапату, поиск остановлен",
            hs->cur.host, key);
        hs->cur.sport = 0;
        finish(hs, now);
        return;
    }
    hs->cur.phase = PH_ACK;
    hs->cur.deadline = now + HS_ACK_MS;
}

static void add_cand(d2k_httpsearch *hs, const char *key) {
    for (size_t i = 0; i < hs->cur.n_cands; i++) { if (!strcmp(hs->cur.cands[i], key)) return; }
    if (hs->cur.n_cands < sizeof hs->cur.cands / sizeof hs->cur.cands[0]) {
        snprintf(hs->cur.cands[hs->cur.n_cands++], sizeof hs->cur.cands[0], "%s", key);
    }
}

static void build_cands(d2k_httpsearch *hs) {
    hs->cur.n_cands = 0;
    hs->cur.idx = 0;
    hs->cur.ok = 0;
    /* Свой план этого имени (перепроверка), затем свои подтверждённые
       планы других имён — свежие первыми, затем вопросы по порядку. */
    rec *own = rec_find(hs, hs->cur.host, hs->cur.family);
    if (own && own->key[0]) { add_cand(hs, own->key); }
    for (;;) {
        const rec *best = NULL;
        for (size_t i = 0; i < hs->n_recs; i++) {
            const rec *r = &hs->recs[i];
            if (!r->key[0]) continue;
            int have = 0;
            for (size_t k = 0; k < hs->cur.n_cands; k++) { if (!strcmp(hs->cur.cands[k], r->key)) have = 1; }
            if (have) continue;
            if (!best || r->seq > best->seq) best = r;
        }
        if (!best) break;
        add_cand(hs, best->key);
    }
    add_cand(hs, "split");
    add_cand(hs, "disorder");
    if (hs->n_measured) {
        /* Порча, измеренная на этой линии, — вместо заготовок. */
        for (size_t i = 0; i < hs->n_measured; i++) { add_cand(hs, hs->measured[i]); }
    } else {
        /* Измеренной нет — заготовки (гипотезы TLS-поиска). */
        add_cand(hs, "fake-badsum");
        add_cand(hs, "fake-seqshift");
    }
}

static void start(d2k_httpsearch *hs, const char *host, uint8_t family, const uint8_t *addr,
                  int recheck, int64_t now) {
    memset(&hs->cur, 0, sizeof hs->cur);
    hs->cur.fd = -1;
    snprintf(hs->cur.host, sizeof hs->cur.host, "%s", host);
    hs->cur.family = family;
    memcpy(hs->cur.addr, addr, family == 6 ? 16 : 4);
    hs->cur.recheck = recheck;
    d2k_hs_job job;
    hs->cur.job_seq = ++hs->job_seq;
    int opened = open_job(hs, &job) == 0;
    job.seq = hs->cur.job_seq;
    if (!opened || !hs->ops.start_probe || hs->ops.start_probe(hs->ops.ctx, &job) != 0) {
        say(hs, "HTTP %s: зонд не запустился — поиск не начат", host);
        drop_socket(hs);
        hs->cur.phase = PH_IDLE;
        return;
    }
    /* База — без пробного плана: проба на этом порту не ставилась. */
    hs->cur.sport = 0;
    hs->cur.phase = PH_BASE;
    hs->cur.deadline = now + (int64_t)d2k_hs_probe_ms * 3;
    say(hs, "HTTP %s: %s — база: тот же запрос своим зондом без плана", host,
        recheck ? "вставка при подтверждённом плане, перепроверка"
                : "вставка провайдера, HTTPS у имени нет — поиск обхода HTTP");
}

static void start_next(d2k_httpsearch *hs, int64_t now) {
    while (hs->cur.phase == PH_IDLE && hs->n_q) {
        pend p = hs->q[0];
        memmove(hs->q, hs->q + 1, (hs->n_q - 1) * sizeof *hs->q);
        hs->n_q--;
        rec *r = rec_find(hs, p.host, p.family);
        start(hs, p.host, p.family, p.addr, r && r->key[0], now);
    }
}

void d2k_httpsearch_portal(d2k_httpsearch *hs, const char *host, uint8_t family,
                           const uint8_t *addr, int64_t now) {
    if (!hs || !addr || (family != 4 && family != 6) || !host_ok(host)) { return; }
    if (hs->cur.phase != PH_IDLE && hs->cur.family == family && !strcasecmp(hs->cur.host, host)) {
        return;
    }
    for (size_t i = 0; i < hs->n_q; i++) {
        if (hs->q[i].family == family && !strcasecmp(hs->q[i].host, host)) { return; }
    }
    rec *r = rec_find(hs, host, family);
    if (r && now < r->no_before_ms) { return; }
    if (hs->cur.phase == PH_IDLE) {
        start(hs, host, family, addr, r && r->key[0], now);
        return;
    }
    if (hs->n_q == hs->cap_q) {
        size_t nc = hs->cap_q ? hs->cap_q * 2 : 8;
        pend *nv = realloc(hs->q, nc * sizeof *nv);
        if (!nv) { return; }
        hs->q = nv;
        hs->cap_q = nc;
    }
    pend *p = &hs->q[hs->n_q++];
    memset(p, 0, sizeof *p);
    snprintf(p->host, sizeof p->host, "%s", host);
    p->family = family;
    memcpy(p->addr, addr, family == 6 ? 16 : 4);
}

void d2k_httpsearch_ack(d2k_httpsearch *hs, const uint8_t trial[16], int ok, int64_t now) {
    if (!hs || hs->cur.phase != PH_ACK || memcmp(trial, hs->cur.trial, 16) != 0) { return; }
    const char *key = hs->cur.cands[hs->cur.idx];
    if (!ok) {
        /* Местный отказ датапата — опыта не было, кандидат не судим. */
        say(hs, "HTTP %s: «%s» — датапат отверг пробный план, кандидат не судим",
            hs->cur.host, key);
        hs->cur.sport = 0;
        hs->cur.ok = 0;
        hs->cur.idx++;
        next_candidate(hs, now);
        return;
    }
    d2k_hs_job job;
    memset(&job, 0, sizeof job);
    hs->cur.job_seq = ++hs->job_seq;
    job.seq = hs->cur.job_seq;
    job.fd = hs->cur.fd;
    job.family = hs->cur.family;
    memcpy(job.addr, hs->cur.addr, sizeof job.addr);
    snprintf(job.host, sizeof job.host, "%s", hs->cur.host);
    if (!hs->ops.start_probe || hs->ops.start_probe(hs->ops.ctx, &job) != 0) {
        say(hs, "HTTP %s: зонд не запустился — поиск остановлен", hs->cur.host);
        drop_probe(hs);
        finish(hs, now);
        return;
    }
    hs->cur.phase = PH_RUN;
    hs->cur.deadline = now + (int64_t)d2k_hs_probe_ms * 3;
}

void d2k_httpsearch_applied(d2k_httpsearch *hs, const uint8_t plan_id[16]) {
    if (!hs || (hs->cur.phase != PH_RUN && hs->cur.phase != PH_APPLIED) ||
        memcmp(plan_id, hs->cur.plan_id, 16) != 0) { return; }
    hs->cur.applied = 1;
    if (hs->cur.phase == PH_APPLIED) {
        d2k_hs_result r = hs->cur.pending;
        judge_trial(hs, &r, hs->cur.deadline - HS_APPLIED_MS);
    }
}

void d2k_httpsearch_result(d2k_httpsearch *hs, const d2k_hs_result *r, int64_t now) {
    if (!hs || !r) { return; }
    if ((hs->cur.phase != PH_BASE && hs->cur.phase != PH_RUN) || r->seq != hs->cur.job_seq) {
        /* Ответ не текущего запуска (ревью M-7): не судит опыт; его сокет
           остался у зонда после остановки по сроку — закрываем здесь. */
        if (r->fd >= 0 && r->fd != hs->cur.fd && hs->ops.close_port) {
            hs->ops.close_port(hs->ops.ctx, r->fd);
        }
        return;
    }
    if (hs->cur.phase == PH_BASE) {
        drop_socket(hs);
        if (r->answer == D2K_HS_INJECTED) {
            build_cands(hs);
            say(hs, "HTTP %s: база — вставка провайдера воспроизведена; вопросов к коробке %zu",
                hs->cur.host, hs->cur.n_cands);
            next_candidate(hs, now);
            return;
        }
        rec *rr = rec_get(hs, hs->cur.host, hs->cur.family);
        if (rr) { rr->no_before_ms = now + D2K_HS_RECHECK_MS; }
        say(hs, "HTTP %s: база — %s%s%s: вставка с роутера не воспроизводится, поиск HTTP "
                "не начат (подозрение не равно блокировке)", hs->cur.host,
            d2k_hs_answer_name(r->answer), r->status[0] ? ", " : "", r->status);
        finish(hs, now);
        return;
    }
    if (hs->cur.phase != PH_RUN) { return; }
    drop_socket(hs);
    drop_probe(hs);
    if (hs->cur.applied) { judge_trial(hs, r, now); return; }
    hs->cur.pending = *r;
    hs->cur.phase = PH_APPLIED;
    hs->cur.deadline = now + HS_APPLIED_MS;
}

void d2k_httpsearch_tick(d2k_httpsearch *hs, int64_t now) {
    if (!hs || hs->cur.phase == PH_IDLE || now < hs->cur.deadline) { return; }
    switch (hs->cur.phase) {
    case PH_ACK:
        say(hs, "HTTP %s: «%s» — датапат не подтвердил пробный план за %d мс, кандидат не судим",
            hs->cur.host, hs->cur.cands[hs->cur.idx], HS_ACK_MS);
        drop_probe(hs);
        hs->cur.ok = 0;
        hs->cur.idx++;
        next_candidate(hs, now);
        break;
    case PH_APPLIED: {
        d2k_hs_result r = hs->cur.pending;
        judge_trial(hs, &r, now);
        break;
    }
    case PH_BASE:
    case PH_RUN:
        /* Зонд не ответил втрое дольше своего срока — что-то сломалось у
           нас; поиск останавливается, сокет закрывается. */
        say(hs, "HTTP %s: зонд не вернулся — поиск остановлен", hs->cur.host);
        if (hs->cur.phase == PH_RUN) { drop_probe(hs); }
        /* Сокет у зонда: его закроет опоздавший ответ, не мы (ревью M-7). */
        hs->cur.fd = -1;
        hs->cur.job_seq = 0;
        finish(hs, now);
        break;
    default:
        break;
    }
}

void d2k_httpsearch_push_all(d2k_httpsearch *hs) {
    if (!hs || !hs->ops.set_plan) { return; }
    for (size_t i = 0; i < hs->n_recs; i++) {
        rec *r = &hs->recs[i];
        if (!r->key[0]) { continue; }
        uint8_t id[16];
        char text[2048];
        stable_id(r->key, id);
        if (d2k_hs_candidate_text(r->key, id, text, sizeof text) == 0) {
            (void)hs->ops.set_plan(hs->ops.ctx, r->host, r->family, text);
        }
    }
}

int d2k_httpsearch_save(d2k_httpsearch *hs, const char *path, int64_t wall_s,
                        char *err, size_t cap) {
    if (!hs || !path) { return -1; }
    char tmp[1100];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        snprintf(err, cap, "путь длиннее %zu", sizeof tmp);
        return -1;
    }
    FILE *f = fopen(tmp, "w");
    if (!f) { snprintf(err, cap, "%s: %s", tmp, strerror(errno)); return -1; }
    fprintf(f, "d2k-http-plans 1\n");
    for (size_t i = 0; i < hs->n_recs; i++) {
        rec *r = &hs->recs[i];
        if (!r->key[0]) { continue; }
        /* Время подтверждения — первое сохранение после него (ревью M-4):
           сохранение идёт сразу за подтверждением. */
        if (!r->wall) { r->wall = wall_s; }
        fprintf(f, "%s %u %s %lld\n", r->host, (unsigned)r->family, r->key, (long long)r->wall);
    }
    int bad = fflush(f) != 0 || fsync(fileno(f)) != 0;
    bad |= fclose(f) != 0;
    if (bad || rename(tmp, path) != 0) {
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

int d2k_httpsearch_load(d2k_httpsearch *hs, const char *path, size_t *n_loaded,
                        char *err, size_t cap) {
    if (n_loaded) { *n_loaded = 0; }
    if (!hs || !path) { return -1; }
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) { return 0; }
        snprintf(err, cap, "%s: %s", path, strerror(errno));
        return -1;
    }
    char line[512];
    if (!fgets(line, sizeof line, f) || strcmp(line, "d2k-http-plans 1\n") != 0) {
        fclose(f);
        snprintf(err, cap, "%s: не планы HTTP d2k (нет заголовка «d2k-http-plans 1»)", path);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char host[300], key[48];
        unsigned family;
        long long wall;
        int used = 0;
        if (sscanf(line, "%299s %u %47s %lld %n", host, &family, key, &wall, &used) != 4 ||
            line[used] != '\0' || (family != 4 && family != 6) || !host_ok(host) ||
            !known_key(key)) { continue; }
        rec *r = rec_get(hs, host, (uint8_t)family);
        if (!r) { break; }
        snprintf(r->key, sizeof r->key, "%.39s", key);
        r->seq = ++hs->seq;
        r->wall = wall;
        uint8_t id[16];
        char text[2048];
        stable_id(key, id);
        if (d2k_hs_candidate_text(key, id, text, sizeof text) == 0 && hs->ops.set_plan) {
            (void)hs->ops.set_plan(hs->ops.ctx, r->host, r->family, text);
        }
        if (n_loaded) { (*n_loaded)++; }
    }
    fclose(f);
    return 0;
}

/* --- рабочий поток ------------------------------------------------------------ */

struct d2k_hs_runner {
    pthread_mutex_t mu;
    pthread_t th;
    int running, joinable, ready;
    d2k_hs_job job;
    d2k_hs_result res;
    int wake[2];
};

static void *runner_main(void *arg) {
    d2k_hs_runner *r = arg;
    d2k_hs_result res;
    d2k_hs_probe_run(&r->job, &res);
    pthread_mutex_lock(&r->mu);
    r->res = res;
    r->ready = 1;
    r->running = 0;
    pthread_mutex_unlock(&r->mu);
    ssize_t w = write(r->wake[1], "x", 1);
    (void)w;
    return NULL;
}

d2k_hs_runner *d2k_hs_runner_new(void) {
    d2k_hs_runner *r = calloc(1, sizeof *r);
    if (!r) { return NULL; }
    if (pipe(r->wake) != 0) { free(r); return NULL; }
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(r->wake[i], F_GETFL, 0);
        if (fl >= 0) { (void)fcntl(r->wake[i], F_SETFL, fl | O_NONBLOCK); }
    }
    pthread_mutex_init(&r->mu, NULL);
    return r;
}

void d2k_hs_runner_free(d2k_hs_runner *r) {
    if (!r) { return; }
    if (r->joinable) { pthread_join(r->th, NULL); }
    close(r->wake[0]);
    close(r->wake[1]);
    pthread_mutex_destroy(&r->mu);
    free(r);
}

int d2k_hs_runner_wake_fd(const d2k_hs_runner *r) { return r ? r->wake[0] : -1; }

int d2k_hs_runner_start(d2k_hs_runner *r, const d2k_hs_job *job) {
    if (!r || !job) { return -1; }
    pthread_mutex_lock(&r->mu);
    int busy = r->running;
    pthread_mutex_unlock(&r->mu);
    if (busy) { return -1; }
    if (r->joinable) { pthread_join(r->th, NULL); r->joinable = 0; }
    r->job = *job;
    r->ready = 0;
    r->running = 1;
    if (pthread_create(&r->th, NULL, runner_main, r) != 0) { r->running = 0; return -1; }
    r->joinable = 1;
    return 0;
}

int d2k_hs_runner_done(d2k_hs_runner *r, d2k_hs_result *out) {
    if (!r || !out) { return 0; }
    char drain[16];
    while (read(r->wake[0], drain, sizeof drain) > 0) { }
    pthread_mutex_lock(&r->mu);
    int ready = r->ready;
    if (ready) { *out = r->res; r->ready = 0; }
    pthread_mutex_unlock(&r->mu);
    if (ready && r->joinable) { pthread_join(r->th, NULL); r->joinable = 0; }
    return ready;
}
