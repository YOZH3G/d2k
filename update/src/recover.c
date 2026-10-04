#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "transaction_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

d2ku_rc d2ku_recover(d2ku_ctx *c, d2ku_status *s) {
    if (!c || !s)
        return D2KU_INVALID;
    int lock = -1;
    d2ku_rc r = d2ku_maintenance_lock(c, &lock);
    if (r != D2KU_OK)
        return r;
    c->maintenance_lock_fd = lock;
    memset(s, 0, sizeof *s);
    r = d2ku_tx_recover_locked(c, s);
    c->maintenance_lock_fd = -1;
    d2ku_maintenance_unlock(lock);
    return r;
}
d2ku_rc d2ku_boot_pulse(int fd, int ready) {
    const char *b = ready ? "D2KU1 READY\n" : "D2KU1 PULSE\n";
    size_t n = strlen(b); /* One PIPE_BUF-sized nonblocking write, with SIGPIPE
                             blocked locally. */
    sigset_t set, old, pending;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (sigprocmask(SIG_BLOCK, &set, &old))
        return D2KU_IO;
    sigpending(&pending);
    ssize_t r;
    do {
        r = write(fd, b, n);
    } while (r < 0 && errno == EINTR);
    if (r < 0 && errno == EPIPE && !sigismember(&pending, SIGPIPE)) {
        int signal_number;
        (void)sigwait(&set, &signal_number);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
    return r == (ssize_t)n ? D2KU_OK : D2KU_IO;
}
static uint64_t millis(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
d2ku_rc d2ku_supervise(d2ku_ctx *c, const char *worker, char *const argv[],
                       d2ku_status *s) {
    if (!c || !worker || !argv || !s)
        return D2KU_INVALID; /* Reconcile previous attempt before allowing a new
                                worker. */
    d2ku_rc rc = d2ku_recover(c, s);
    if (rc != D2KU_OK)
        return rc;
    int fds[2];
    if (pipe(fds))
        return D2KU_IO;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return D2KU_IO;
    }
    if (!pid) {
        setpgid(0, 0);
        close(fds[0]);
        if (dup2(fds[1], 3) < 0)
            _exit(126);
        if (fds[1] != 3)
            close(fds[1]);
        fcntl(3, F_SETFD, 0);
        fcntl(3, F_SETFL, O_NONBLOCK);
        execv(worker, argv);
        _exit(127);
    }
    setpgid(pid, pid);
    close(fds[1]);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    uint64_t last = millis();
    char line[64];
    size_t used = 0;
    int status = 0, reaped = 0, bad = 0;
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            reaped = 1;
            break;
        }
        if (w < 0 && errno != EINTR) {
            bad = 1;
            break;
        }
        struct pollfd p = {fds[0], POLLIN, 0};
        int n = poll(&p, 1, 100);
        if (n < 0 && errno != EINTR) {
            bad = 1;
            break;
        }
        for (;;) {
            char ch;
            ssize_t z = read(fds[0], &ch, 1);
            if (z < 0 && (errno == EAGAIN || errno == EINTR))
                break;
            if (z == 0)
                break;
            if (z < 0) {
                bad = 1;
                break;
            }
            if (used == sizeof line - 1) {
                bad = 1;
                break;
            }
            line[used++] = ch;
            if (ch == '\n') {
                line[used] = 0;
                if (strcmp(line, "D2KU1 PULSE\n") &&
                    strcmp(line, "D2KU1 READY\n")) {
                    bad = 1;
                    break;
                }
                used = 0;
                last = millis();
            }
        }
        if (bad || millis() - last >= D2KU_HEARTBEAT_MS) {
            bad = 1;
            break;
        }
    }
    /* Always terminate the owned group, including descendants holding service
     * or lock descriptors, before attempting recovery. No candidate curl
     * dependency.
     */
    kill(-pid, SIGKILL);
    if (!reaped) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
    }
    close(fds[0]);
    d2ku_journal j;
    rc = d2ku_journal_load(c, &j);
    int incomplete = rc == D2KU_OK && j.phase != D2KU_COMMITTED &&
                     j.phase != D2KU_ROLLED_BACK;
    rc = d2ku_recover(c, s);
    if (rc != D2KU_OK)
        return rc;
    return bad || incomplete || !WIFEXITED(status) || WEXITSTATUS(status)
               ? D2KU_HEALTH
               : D2KU_OK;
}
