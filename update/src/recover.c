#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "lifecycle.h"
#include "startup.h"
#include "transaction_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <time.h>
#include <unistd.h>

d2ku_rc d2ku_recover(d2ku_ctx *c, d2ku_status *s) {
    if (!c || !s)
        return D2KU_INVALID;
    int lock = -1;
    d2ku_rc r = d2ku_maintenance_wait(c, &lock);
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
      sigset_t after;
      sigpending(&after);
      if (sigismember(&after, SIGPIPE)) {
        int signal_number;
        (void)sigwait(&set, &signal_number);
      }
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
/* The gate owner sends exactly one bounded frame at a time on bootstrap FD5.
 * Group registration is durable only for this supervisor lifetime, never disk.
 */
#define GROUPS_MAX 16
static void group_frame(unsigned char b[8], const char *magic, pid_t pid) {
    memcpy(b, magic, 4);
    uint32_t n = (uint32_t)pid;
    for (unsigned k = 0; k < 4; k++)
        b[7 - k] = (unsigned char)(n >> (8 * k));
}
static pid_t frame_pid(const unsigned char b[8]) {
    uint32_t n = 0;
    for (unsigned k = 4; k < 8; k++)
        n = (n << 8) | b[k];
    return n > 1 && n <= INT32_MAX ? (pid_t)n : -1;
}
static d2ku_rc send_frame(d2ku_ctx *c, int fd, const unsigned char b[8]) {
    size_t used = 0;
    uint64_t end = millis() + 5000;
    while (used < 8 && millis() < end) {
        ssize_t n;
        if (c && c->write_fd)
            n = c->write_fd(c->io_arg, fd, b + used, 8 - used);
        else {
#ifdef MSG_NOSIGNAL
            n = send(fd, b + used, 8 - used, MSG_NOSIGNAL);
#else
            n = send(fd, b + used, 8 - used, 0);
#endif
        }
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd p = {fd, POLLOUT, 0};
            poll(&p, 1, 20);
            continue;
        }
        return D2KU_IO;
    }
    return used == 8 ? D2KU_OK : D2KU_IO;
}
d2ku_rc d2ku_boot_group(d2ku_ctx *c, pid_t pid, int registering) {
    if (c->boot_control_fd <= 2)
        return D2KU_OK;
    unsigned char b[8], reply[8];
    group_frame(b, registering ? "D2GR" : "D2GU", pid);
    if (send_frame(c, c->boot_control_fd, b) != D2KU_OK)
        return D2KU_IO;
    size_t used = 0;
    uint64_t end = millis() + 5000;
    while (used < 8 && millis() < end) {
        ssize_t n = read(c->boot_control_fd, reply + used, 8 - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n == 0)
            return D2KU_IO;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return D2KU_IO;
        struct pollfd p = {c->boot_control_fd, POLLIN, 0};
        poll(&p, 1, 20);
    }
    group_frame(b, "D2GA", pid);
    return used == 8 && !memcmp(b, reply, 8) ? D2KU_OK : D2KU_IO;
}
d2ku_rc d2ku_group_cleanup(pid_t group) {
    if (group <= 1 || group == getpgrp())
        return D2KU_INVALID;
    (void)kill(-group, SIGKILL);
    uint64_t end = millis() + 5000;
    for (;;) {
        while (waitpid(-group, NULL, WNOHANG) > 0) {
        }
        if (kill(-group, 0) < 0 && errno == ESRCH)
            return D2KU_OK;
        if (millis() >= end)
            return D2KU_RECOVERY;
        struct timespec t = {0, 10000000};
        nanosleep(&t, NULL);
    }
}
static d2ku_rc control_frame(int fd, const unsigned char b[8], pid_t worker,
                             pid_t groups[GROUPS_MAX]) {
    pid_t pid = frame_pid(b);
    if (pid < 0 || pid == worker)
        return D2KU_INVALID;
    size_t slot = GROUPS_MAX;
    for (size_t k = 0; k < GROUPS_MAX; k++)
        if (groups[k] == pid) {
            slot = k;
            break;
        }
    if (!memcmp(b, "D2GR", 4)) {
        if (slot != GROUPS_MAX)
            return D2KU_INVALID;
        pid_t group = getpgid(pid);
        if (group != worker)
            return D2KU_INVALID;
        for (size_t k = 0; k < GROUPS_MAX; k++)
            if (!groups[k]) {
                slot = k;
                break;
            }
        if (slot == GROUPS_MAX)
            return D2KU_BUSY;
        groups[slot] = pid;
    } else if (!memcmp(b, "D2GU", 4)) {
        if (slot == GROUPS_MAX)
            return D2KU_INVALID;
        if (d2ku_group_cleanup(pid) != D2KU_OK)
            return D2KU_RECOVERY;
        groups[slot] = 0;
    } else
        return D2KU_INVALID;
    unsigned char ack[8];
    group_frame(ack, "D2GA", pid);
    return send_frame(NULL, fd, ack);
}
static d2ku_rc supervise_worker(d2ku_ctx *c, const char *worker,
                                char *const argv[], d2ku_status *s) {
  if (!c || !worker || !argv || !s)
    return D2KU_INVALID; /* Reconcile previous attempt before allowing a new
                            worker. */
  d2ku_rc rc = d2ku_recover(c, s);
  if (rc != D2KU_OK)
    return rc;
#ifdef __linux__
    if (prctl(PR_SET_CHILD_SUBREAPER, 1))
        return D2KU_IO;
#endif
    char initial_release[D2KU_ID_MAX + 1];
    rc = d2ku_tx_current(c, initial_release);
    if (rc != D2KU_OK)
      return rc;
    d2ku_journal before;
    uint64_t initial_sequence =
        d2ku_journal_load(c, &before) == D2KU_OK ? before.sequence : 0;
    int fds[2], control[2];
    if (pipe(fds))
        return D2KU_IO;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, control)) {
        close(fds[0]);
        close(fds[1]);
        return D2KU_IO;
    }
    for (unsigned k = 0; k < 2; k++) {
        fcntl(control[k], F_SETFL, O_NONBLOCK);
        fcntl(control[k], F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
        int one = 1;
        setsockopt(control[k], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        close(control[0]);
        close(control[1]);
        return D2KU_IO;
    }
    if (!pid) {
        setpgid(0, 0);
        close(fds[0]);
        close(control[0]);
        int control_copy = fcntl(control[1], F_DUPFD_CLOEXEC, 10);
        if (control_copy < 0)
            _exit(126);
        close(control[1]);
        if (dup2(fds[1], 3) < 0)
            _exit(126);
        if (fds[1] != 3)
            close(fds[1]);
        fcntl(3, F_SETFD, 0);
        fcntl(3, F_SETFL, O_NONBLOCK);
        if (dup2(control_copy, 5) < 0)
            _exit(126);
        close(control_copy);
        fcntl(5, F_SETFD, 0);
        execv(worker, argv);
        _exit(127);
    }
    setpgid(pid, pid);
    close(fds[1]);
    close(control[1]);
    pid_t groups[GROUPS_MAX] = {0};
    unsigned char request[8];
    size_t request_used = 0;
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
        /* Супервизор — subreaper: демоны служб, запущенные транзакцией через
         * start-stop-daemon -b, усыновляются им. Не собранный потомок остаётся
         * зомби, S99d2k считает его живым, и управляемая остановка срывается. */
        for (;;) {
            int stray_status;
            pid_t stray = waitpid(-1, &stray_status, WNOHANG);
            if (stray <= 0)
                break;
            if (stray == pid) {
                status = stray_status;
                reaped = 1;
                break;
            }
        }
        if (reaped)
            break;
        struct pollfd pollfds[2] = {{fds[0], POLLIN, 0},
                                    {control[0], POLLIN, 0}};
        int n = poll(pollfds, 2, 100);
        if (n < 0 && errno != EINTR) {
            bad = 1;
            break;
        }
        for (;;) {
            ssize_t got =
                read(control[0], request + request_used, 8 - request_used);
            if (got < 0 &&
                (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            if (got <= 0)
                break;
            request_used += (size_t)got;
            if (request_used == 8) {
                if (control_frame(control[0], request, pid, groups) !=
                    D2KU_OK) {
                    bad = 1;
                    break;
                }
                request_used = 0;
            }
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
    close(control[0]);
    /* The pre-registration child stays in worker's group; only ACKed children
     * may move to registered groups. Reap these groups before touching state.
     */
    if (d2ku_group_cleanup(pid) != D2KU_OK)
        return D2KU_RECOVERY;
    for (size_t k = 0; k < GROUPS_MAX; k++)
        if (groups[k] && d2ku_group_cleanup(groups[k]) != D2KU_OK)
            return D2KU_RECOVERY;
    if (!bad && reaped && WIFEXITED(status) && WEXITSTATUS(status) == 76 &&
        c->supervisor_quiesce && c->supervisor_quiesce(c, pid) == D2KU_OK)
      return D2KU_QUIESCED_RC;
    d2ku_journal j;
    rc = d2ku_journal_load(c, &j);
    int handoff = !bad && reaped && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 75 && rc == D2KU_OK &&
                  j.phase == D2KU_COMMITTED && j.sequence > initial_sequence &&
                  !strcmp(j.old_release_id, initial_release) &&
                  strcmp(j.new_release_id, initial_release);
    if (handoff) {
      char current[D2KU_ID_MAX + 1];
      unsigned char hash[32];
      handoff = d2ku_tx_current(c, current) == D2KU_OK &&
                !strcmp(current, j.new_release_id) &&
                d2ku_tx_receipt(c, current, hash) == D2KU_OK &&
                !memcmp(hash, j.new_manifest_sha256, 32);
    }
    int incomplete = rc == D2KU_OK && j.phase != D2KU_COMMITTED &&
                     j.phase != D2KU_ROLLED_BACK;
    rc = d2ku_recover(c, s);
    if (rc != D2KU_OK)
        return rc;
    if (handoff)
      return D2KU_HANDOFF_RC;
    return bad || incomplete || !WIFEXITED(status) || WEXITSTATUS(status)
               ? D2KU_HEALTH
               : D2KU_OK;
}

/* Standalone supervisor CLI and stable daemon loop share the same ownership
 * lock. The latter passes its held descriptor across successive workers. */
d2ku_rc d2ku_supervise(d2ku_ctx *c, const char *worker, char *const argv[],
                       d2ku_status *s) {
  if (!c)
    return D2KU_INVALID;
  if (c->supervisor_lock_fd > 2)
    return supervise_worker(c, worker, argv, s);
  int fd = -1, guard = -1;
  d2ku_rc claimed = d2ku_startup_claim(c, "supervisor.lock", &guard, &fd);
  if (claimed != D2KU_OK)
    return claimed;
  d2ku_maintenance_unlock(guard);
  c->supervisor_lock_fd = fd;
  d2ku_rc r = supervise_worker(c, worker, argv, s);
  c->supervisor_lock_fd = -1;
  close(fd);
  return r;
}
