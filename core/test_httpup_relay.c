#define _GNU_SOURCE
#undef NDEBUG /* asserts carry the side effects; zig cc -O2 defines NDEBUG */
/* relay() must not spin after one side half-closes (field 2026-10-02: 194% CPU).
   httpup.c is included to reach the static relay(); IDLE_MS is shortened. */
#define D2K_HTTPUP_NO_MAIN 1
#define IDLE_MS 1500
#ifndef SO_MARK
#define SO_MARK 36 /* Linux-only; connect path is not exercised here */
#endif
#include <poll.h>
#include <stdio.h>

/* Linux reports POLLHUP/POLLERR even for events=0, so a closed side must be
   dropped from the set (fd=-1), not kept with events=0. This hook checks that
   on any host, since macOS poll does not reproduce the spin itself. */
static int polls_total, polls_inert;
static int test_poll(struct pollfd *p, nfds_t n, int ms) {
    polls_total++;
    for (nfds_t i = 0; i < n; i++) {
        if (p[i].fd >= 0 && p[i].events == 0) { polls_inert++; }
    }
    return (poll)(p, n, ms);
}
#define poll(p, n, ms) test_poll(p, n, ms)
#include "httpup.c"

#include <assert.h>

struct args { int client, upstream; long cpu_ms; long wall_ms; };

static long now_ms(clockid_t c) {
    struct timespec t; clock_gettime(c, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void *run(void *v) {
    struct args *a = v;
    long w = now_ms(CLOCK_MONOTONIC), c = now_ms(CLOCK_THREAD_CPUTIME_ID);
    relay(a->client, a->upstream);
    a->cpu_ms = now_ms(CLOCK_THREAD_CPUTIME_ID) - c;
    a->wall_ms = now_ms(CLOCK_MONOTONIC) - w;
    return NULL;
}

/* Explicit stack: musl's default thread stack is only 128 KB. */
static void spawn(pthread_t *th, struct args *a) {
    pthread_attr_t at;
    assert(pthread_attr_init(&at) == 0);
    assert(pthread_attr_setstacksize(&at, 1024 * 1024) == 0);
    assert(pthread_create(th, &at, run, a) == 0);
    pthread_attr_destroy(&at);
}

static void pair(int *proxy_side, int *peer_side) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    *proxy_side = sv[0]; *peer_side = sv[1];
}

static void read_exact(int fd, const char *want) {
    char b[64]; size_t n = strlen(want), got = 0;
    while (got < n) {
        ssize_t r = recv(fd, b + got, n - got, 0);
        assert(r > 0); got += (size_t)r;
    }
    assert(memcmp(b, want, n) == 0);
}

/* half_only: client shuts only its write side and still reads the reply;
   otherwise the client closes entirely. Upstream stays silent and open. */
static void scenario(int half_only) {
    polls_inert = 0; polls_total = 0;
    int pc, client, pu, upstream;
    pair(&pc, &client); pair(&pu, &upstream);
    struct args a = { pc, pu, 0, 0 };
    pthread_t th = 0;
    spawn(&th, &a);
    assert(send(client, "req", 3, 0) == 3);
    if (half_only) { shutdown(client, SHUT_WR); } else { close(client); }
    read_exact(upstream, "req");
    char b[8];
    assert(recv(upstream, b, sizeof b, 0) == 0);      /* FIN propagated */
    if (half_only) {                                   /* tail of the reply still arrives */
        usleep(200000);
        assert(send(upstream, "tail", 4, 0) == 4);
        read_exact(client, "tail");
        shutdown(upstream, SHUT_WR);
        assert(recv(client, b, sizeof b, 0) == 0);
    }
    pthread_join(th, NULL);
    printf("half_only=%d cpu=%ldms wall=%ldms\n", half_only, a.cpu_ms, a.wall_ms);
    assert(a.cpu_ms < 50);
    assert(polls_inert == 0);
    assert(polls_total < 20);
    polls_total = 0;
    if (!half_only) {                                  /* silent upstream: idle timeout ends it */
        assert(a.wall_ms >= IDLE_MS - 200 && a.wall_ms < IDLE_MS + 1000);
    }
    if (half_only) { close(client); }
    close(upstream); close(pc); close(pu);
}

/* TCP client aborts with RST (SO_LINGER 1,0); upstream silent: relay must end
   quickly through the recv error, not wait for the idle timeout. */
static void scenario_rst(void) {
    polls_inert = 0; polls_total = 0;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(0x7f000001u);
    assert(bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 1) == 0);
    socklen_t sl = sizeof sa; assert(getsockname(ls, (struct sockaddr *)&sa, &sl) == 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(client, (struct sockaddr *)&sa, sizeof sa) == 0);
    int pc = accept(ls, NULL, NULL); assert(pc >= 0);
    int pu, upstream; pair(&pu, &upstream);
    struct args a = { pc, pu, 0, 0 };
    pthread_t th = 0;
    spawn(&th, &a);
    struct linger lg = { 1, 0 };
    assert(setsockopt(client, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) == 0);
    close(client);
    pthread_join(th, NULL);
    printf("rst cpu=%ldms wall=%ldms\n", a.cpu_ms, a.wall_ms);
    assert(a.cpu_ms < 50 && a.wall_ms < 1000);
    assert(polls_inert == 0 && polls_total < 20);
    close(upstream); close(pc); close(pu); close(ls);
}

/* Old code never returns from relay() (poll always ready): fail instead of hang. */
static void watchdog(int sig) {
    static const char m[] = "FAIL: relay() did not return in time (busy loop)\n";
    (void)sig;
    if (write(2, m, sizeof m - 1) < 0) { _exit(3); }
    _exit(2);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, watchdog);
    alarm(12);
    signal(SIGPIPE, SIG_IGN);
    scenario(0);
    scenario(1);
    scenario_rst();
    puts("test_httpup_relay: ok");
    return 0;
}
