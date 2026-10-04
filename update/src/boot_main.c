#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_update.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Stable bootstrap executable. It links no transport/curl and executes only the
 * installed bootstrap-owned C adapter. Candidate archives cannot replace boot/.
 */
static d2ku_rc mono(void *arg, uint64_t *n) {
    (void)arg;
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return D2KU_TIME;
    *n = (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
    return D2KU_OK;
}
static d2ku_rc sample(void *arg, d2ku_clock_sample *s) {
    (void)arg;
    memset(s, 0, sizeof *s);
    uint64_t n;
    if (mono(NULL, &n) != D2KU_OK)
        return D2KU_TIME;
    s->mono_ms = n / 1000000;
    int fd = open("/proc/sys/kernel/random/boot_id",
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return D2KU_TIME;
    ssize_t k = read(fd, s->boot_id, sizeof s->boot_id - 1);
    close(fd);
    if (k <= 0)
        return D2KU_TIME;
    s->boot_id[k] = 0;
    s->boot_id[strcspn(s->boot_id, "\n")] = 0;
    return D2KU_OK;
}
static d2ku_rc adapter(d2ku_ctx *c, const char *action, const char *release,
                       uint64_t mask) {
    int boot = openat(c->root_dirfd, "boot",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (boot < 0)
        return D2KU_IO;
    struct stat st;
    int binary =
        openat(boot, "d2k-service-adapter", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (binary < 0) {
        close(boot);
        return D2KU_IO;
    }
    int good = !fstat(binary, &st) && S_ISREG(st.st_mode) &&
               st.st_uid == geteuid() && !(st.st_mode & 022) &&
               st.st_nlink == 1;
    close(binary);
    if (!good) {
        close(boot);
        return D2KU_INVALID;
    }
    pid_t p = fork();
    if (p < 0) {
        close(boot);
        return D2KU_IO;
    }
    if (!p) {
        setpgid(0, 0);
        if (fchdir(boot))
            _exit(126);
        close(boot);
        if (c->maintenance_lock_fd < 0 || dup2(c->maintenance_lock_fd, 4) < 0)
            _exit(126);
        fcntl(4, F_SETFD, 0);
        char bits[24];
        snprintf(bits, sizeof bits, "%llu", (unsigned long long)mask);
        execl("./d2k-service-adapter", "d2k-service-adapter",
              "--maintenance-fd", "4", action, release, bits, (char *)NULL);
        _exit(127);
    }
    setpgid(p, p);
    close(boot);
    uint64_t start, now;
    mono(NULL, &start);
    int status = 0;
    for (;;) {
        pid_t w = waitpid(p, &status, WNOHANG);
        if (w == p) {
            return WIFEXITED(status) && !WEXITSTATUS(status) ? D2KU_OK
                                                             : D2KU_HEALTH;
        }
        if (w < 0 && errno != EINTR)
            break;
        if (mono(NULL, &now) != D2KU_OK || now - start >= UINT64_C(30000000000))
            break;
        struct timespec t = {0, 10000000};
        nanosleep(&t, NULL);
    }
    kill(-p, SIGKILL);
    kill(p, SIGKILL);
    while (waitpid(p, NULL, 0) < 0 && errno == EINTR) {
    }
    return D2KU_HEALTH;
}
static d2ku_rc services(void *p, const char *action, const char *release,
                        uint64_t mask) {
    return adapter(p, action, release, mask);
}
static d2ku_rc state(void *p) { return adapter(p, "health-state", "-", 0); }
static d2ku_rc rules(void *p) { return adapter(p, "health-rules", "-", 0); }
static d2ku_rc http(void *p) { return adapter(p, "health-http", "-", 0); }
int main(int argc, char **argv) {
    const char *root = "/opt/d2k", *runtime = "/tmp/d2k";
    int at = 1;
    if (argc == 2 && !strcmp(argv[1], "--boot-protocol")) {
        puts("1");
        return 0;
    }
    if (at + 1 < argc && !strcmp(argv[at], "--root")) {
        root = argv[at + 1];
        at += 2;
    }
    if (at + 1 < argc && !strcmp(argv[at], "--runtime")) {
        runtime = argv[at + 1];
        at += 2;
    }
    if (at >= argc ||
        (strcmp(argv[at], "--recover") && strcmp(argv[at], "--supervise"))) {
        fprintf(stderr, "usage: d2k-update-boot [--root DIR] [--runtime DIR] "
                        "--recover | --supervise WORKER [ARGS...]\n");
        return 2;
    }
    d2ku_ctx c = {0};
    c.maintenance_lock_fd = -1;
    c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    c.health_runtime_dirfd =
        open(runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (c.root_dirfd < 0 || fstat(c.root_dirfd, &st) ||
        st.st_uid != geteuid() || (st.st_mode & 022)) {
        fprintf(stderr, "invalid update root\n");
        return 1;
    }
    c.updater_version = 1;
    c.wire_version = 13;
    c.state_version = 1;
    c.clock.monotonic = mono;
    c.clock.snapshot = sample;
    c.transaction.arg = &c;
    c.transaction.services = services;
    c.health_arg = &c;
    c.health_state = state;
    c.health_rules = rules;
    c.health_http = http;
    d2ku_status s = {0};
    d2ku_rc r;
    if (!strcmp(argv[at], "--recover"))
        r = at + 1 == argc ? d2ku_recover(&c, &s) : D2KU_INVALID;
    else
        r = at + 1 < argc ? d2ku_supervise(&c, argv[at + 1], &argv[at + 1], &s)
                          : D2KU_INVALID;
    if (c.health_runtime_dirfd >= 0)
        close(c.health_runtime_dirfd);
    close(c.root_dirfd);
    if (r != D2KU_OK)
        fprintf(stderr, "update recovery result=%d\n", (int)r);
    return r == D2KU_OK ? 0 : 1;
}
