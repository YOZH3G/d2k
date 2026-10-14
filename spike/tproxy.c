/* tproxy.c — опыт 09.10 (задача 12): цена прозрачного прокси как исполнителя.
 *
 * Вопрос опыта один: во что обходится роутеру перекачка ВСЕХ байтов
 * проксированного соединения через userspace по сравнению с нынешним путём
 * (датапат видит первые пакеты, дальше поток в ядре или в ускорителе).
 * Поэтому здесь нет ни плана, ни приёмов: соединение клиента, пришедшее
 * через nat REDIRECT, принимается, к исходному адресу (SO_ORIGINAL_DST)
 * открывается своё, и байты перекачиваются в обе стороны. Первые байты на
 * исходящем соединении исполняет нынешний датапат — для цифр пропускной
 * способности и процессора это безразлично.
 *
 * Перекачка — splice() через pipe, без копирования в userspace; --copy
 * переключает на read()/write() для сравнения. Только Linux, только IPv4.
 *
 *   tproxy --port 1444 [--copy] [--stats 5] [--mark 0x2c]
 *
 * --mark ставит SO_MARK на исходящие сокеты: в лаборатории перехват идёт в
 * nat OUTPUT, и без метки собственное соединение прокси ушло бы в него же.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#define PIPE_CAP  (64 * 1024)   /* ёмкость pipe по умолчанию в Linux */
#define COPY_BUF  (64 * 1024)
#define MAX_EV    64

typedef struct dir {
    int from, to;          /* сокеты направления */
    int p[2];              /* pipe для splice; -1 в режиме --copy */
    size_t inpipe;         /* байт в pipe (или в буфере) */
    uint8_t *buf;          /* буфер режима --copy */
    size_t off;            /* смещение отправки в буфере */
    int eof;               /* источник закрыт для чтения */
    int done;              /* EOF доставлен: shutdown(to, SHUT_WR) */
} dir;

typedef struct pair {
    int cfd, ufd;
    int connecting;        /* исходящее соединение ещё не установлено */
    dir up, down;          /* клиент→сервер, сервер→клиент */
    uint32_t ev_c, ev_u;   /* текущий интерес epoll */
} pair;

/* Метка epoll: указатель на пару, младший бит — какой из двух сокетов. */
#define TAG(p, isu) ((uint64_t)(uintptr_t)(p) | (uint64_t)(isu))

static int ep, use_copy;
static unsigned mark;
static volatile sig_atomic_t stop;
static unsigned long long tot_up, tot_down, accepted, refused;
static long active;

static void on_sig(int s) { (void)s; stop = 1; }

static void dir_init(dir *d, int from, int to) {
    memset(d, 0, sizeof *d);
    d->from = from; d->to = to; d->p[0] = d->p[1] = -1;
}

static int dir_alloc(dir *d) {
    if (use_copy) { d->buf = malloc(COPY_BUF); return d->buf ? 0 : -1; }
    if (pipe2(d->p, O_NONBLOCK | O_CLOEXEC) != 0) { return -1; }
    return 0;
}

static void dir_free(dir *d) {
    if (d->p[0] >= 0) { close(d->p[0]); close(d->p[1]); }
    free(d->buf);
}

static void pair_close(pair *p) {
    epoll_ctl(ep, EPOLL_CTL_DEL, p->cfd, NULL);
    if (p->ufd >= 0) { epoll_ctl(ep, EPOLL_CTL_DEL, p->ufd, NULL); close(p->ufd); }
    close(p->cfd);
    dir_free(&p->up); dir_free(&p->down);
    free(p);
    active--;
}

/* Интерес по заполненности: читать источник, пока есть место; писать в
   приёмник, пока есть что. Полный pipe сам даёт обратное давление. */
static void rearm(pair *p) {
    uint32_t c = 0, u = 0;
    if (p->connecting) {
        u = EPOLLOUT;
    } else {
        size_t cap = use_copy ? COPY_BUF : PIPE_CAP;
        if (!p->up.eof && p->up.inpipe < cap)     { c |= EPOLLIN; }
        if (p->up.inpipe)                          { u |= EPOLLOUT; }
        if (!p->down.eof && p->down.inpipe < cap) { u |= EPOLLIN; }
        if (p->down.inpipe)                        { c |= EPOLLOUT; }
    }
    struct epoll_event e;
    if (c != p->ev_c) {
        e.events = c; e.data.u64 = TAG(p, 0);
        epoll_ctl(ep, EPOLL_CTL_MOD, p->cfd, &e); p->ev_c = c;
    }
    if (u != p->ev_u) {
        e.events = u; e.data.u64 = TAG(p, 1);
        epoll_ctl(ep, EPOLL_CTL_MOD, p->ufd, &e); p->ev_u = u;
    }
}

/* Один шаг направления: забрать из источника, отдать в приёмник.
   0 — живо, -1 — ошибка соединения. */
static int pump(dir *d, unsigned long long *total) {
    size_t cap = use_copy ? COPY_BUF : PIPE_CAP;
    if (!d->eof && d->inpipe < cap) {
        ssize_t n;
        if (use_copy) {
            if (d->inpipe == 0) { d->off = 0; }
            n = d->off + d->inpipe < COPY_BUF
                ? read(d->from, d->buf + d->off + d->inpipe, COPY_BUF - d->off - d->inpipe) : -2;
        } else {
            n = splice(d->from, NULL, d->p[1], NULL, cap - d->inpipe,
                       SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        }
        if (n > 0) { d->inpipe += (size_t)n; }
        else if (n == 0) { d->eof = 1; }
        else if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) { return -1; }
    }
    if (d->inpipe) {
        ssize_t n = use_copy
            ? write(d->to, d->buf + d->off, d->inpipe)
            : splice(d->p[0], NULL, d->to, NULL, d->inpipe, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (n > 0) { d->inpipe -= (size_t)n; d->off += (size_t)n; *total += (unsigned long long)n; }
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { return -1; }
    }
    if (d->eof && d->inpipe == 0 && !d->done) {
        shutdown(d->to, SHUT_WR);
        d->done = 1;
    }
    return 0;
}

static void on_accept(int lfd) {
    for (;;) {
        int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) { return; }
        struct sockaddr_in dst; socklen_t dl = sizeof dst;
        struct sockaddr_in me;  socklen_t ml = sizeof me;
        if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &dst, &dl) != 0 ||
            getsockname(cfd, (struct sockaddr *)&me, &ml) != 0 ||
            (dst.sin_addr.s_addr == me.sin_addr.s_addr && dst.sin_port == me.sin_port)) {
            /* Не через REDIRECT или прямо на нас — петля, не проксируем. */
            refused++; close(cfd); continue;
        }
        int ufd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        pair *p = ufd >= 0 ? calloc(1, sizeof *p) : NULL;
        if (!p) { if (ufd >= 0) close(ufd); close(cfd); refused++; continue; }
        p->cfd = cfd; p->ufd = ufd; p->connecting = 1;
        dir_init(&p->up, cfd, ufd); dir_init(&p->down, ufd, cfd);
        active++;
        int one = 1;
        if (mark) { setsockopt(ufd, SOL_SOCKET, SO_MARK, &mark, sizeof mark); }
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (dir_alloc(&p->up) != 0 || dir_alloc(&p->down) != 0 ||
            (connect(ufd, (struct sockaddr *)&dst, sizeof dst) != 0 && errno != EINPROGRESS)) {
            refused++;
            p->ufd = -1; close(ufd);
            dir_free(&p->up); dir_free(&p->down); close(cfd); free(p); active--;
            continue;
        }
        struct epoll_event e;
        e.events = 0;        e.data.u64 = TAG(p, 0); epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &e);
        e.events = EPOLLOUT; e.data.u64 = TAG(p, 1); epoll_ctl(ep, EPOLL_CTL_ADD, ufd, &e);
        p->ev_c = 0; p->ev_u = EPOLLOUT;
        accepted++;
    }
}

static void on_event(pair *p, int isu, uint32_t events) {
    if (p->connecting) {
        int err = 0; socklen_t el = sizeof err;
        if (!isu) { return; }
        if (getsockopt(p->ufd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            pair_close(p); return;
        }
        p->connecting = 0;
        rearm(p);
        return;
    }
    if (events & (EPOLLERR)) { pair_close(p); return; }
    if (pump(&p->up, &tot_up) != 0 || pump(&p->down, &tot_down) != 0) {
        pair_close(p); return;
    }
    if (p->up.done && p->down.done) { pair_close(p); return; }
    if ((events & EPOLLHUP) && p->up.eof && p->down.eof &&
        !p->up.inpipe && !p->down.inpipe) { pair_close(p); return; }
    rearm(p);
}

static double now_s(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static double cpu_s(void) {
    struct rusage r; getrusage(RUSAGE_SELF, &r);
    return (double)r.ru_utime.tv_sec + r.ru_utime.tv_usec / 1e6 +
           (double)r.ru_stime.tv_sec + r.ru_stime.tv_usec / 1e6;
}

int main(int argc, char **argv) {
    int port = 1444, every = 5;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) { port = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--stats") && i + 1 < argc) { every = atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--copy")) { use_copy = 1; }
        else if (!strcmp(argv[i], "--mark") && i + 1 < argc) { mark = (unsigned)strtoul(argv[++i], NULL, 0); }
        else { fprintf(stderr, "usage: tproxy --port N [--copy] [--stats S] [--mark M]\n"); return 2; }
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), one = 1;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port); a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (lfd < 0 || setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
        bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 256) != 0) {
        perror("tproxy: listen"); return 1;
    }
    ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event e; e.events = EPOLLIN; e.data.u64 = 0;
    epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &e);
    fprintf(stderr, "tproxy: порт %d, перекачка %s\n", port, use_copy ? "read/write" : "splice");

    double t0 = now_s(), last = t0, c0 = cpu_s(), lc = c0;
    unsigned long long lu = 0, ld = 0;
    struct epoll_event evs[MAX_EV];
    while (!stop) {
        int n = epoll_wait(ep, evs, MAX_EV, 1000);
        for (int i = 0; i < n; i++) {
            uint64_t t = evs[i].data.u64;
            if (t == 0) { on_accept(lfd); continue; }
            on_event((pair *)(uintptr_t)(t & ~(uint64_t)1), (int)(t & 1), evs[i].events);
        }
        double now = now_s();
        if (every > 0 && now - last >= every) {
            double dt = now - last, dc = cpu_s() - lc;
            fprintf(stderr, "tproxy: %.0f с: к серверу %.1f Мбит/с, к клиенту %.1f Мбит/с, "
                    "процессор %.1f%% ядра, пар %ld, принято %llu, отказано %llu\n",
                    now - t0, (tot_up - lu) * 8 / dt / 1e6, (tot_down - ld) * 8 / dt / 1e6,
                    dc / dt * 100, active, accepted, refused);
            last = now; lc = cpu_s(); lu = tot_up; ld = tot_down;
        }
    }
    double dt = now_s() - t0;
    fprintf(stderr, "tproxy: итог за %.0f с: к серверу %llu байт, к клиенту %llu байт, "
            "процессор %.1f с (%.1f%% ядра в среднем)\n",
            dt, tot_up, tot_down, cpu_s() - c0, (cpu_s() - c0) / (dt > 0 ? dt : 1) * 100);
    return 0;
}
