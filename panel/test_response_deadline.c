#define _POSIX_C_SOURCE 200809L
#include "server.c"
#include <assert.h>

int main(void) {
    assert(d2k_panel_ignore_sigpipe() == 0);
    int fds[2]; assert(pipe(fds) == 0);
    int flags = fcntl(fds[1], F_GETFL); assert(flags >= 0);
    assert(response(fds[1], 200, "OK", "text/plain", "complete\n", 9) == 0);
    assert(fcntl(fds[1], F_GETFL) == flags);
    close(fds[1]);
    char small[2048]; ssize_t n = read(fds[0], small, sizeof small - 1);
    assert(n > 0); small[n] = '\0';
    assert(strstr(small, "HTTP/1.1 200 OK\r\n"));
    assert(strstr(small, "\r\n\r\ncomplete\n")); close(fds[0]);

    assert(pipe(fds) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(fds[1]);
        char chunk[4096];
        struct timespec pause = { .tv_nsec = 20000000 };
        for (int i = 0; i < 25; i++) {
            nanosleep(&pause, NULL);
            if (read(fds[0], chunk, sizeof chunk) <= 0) break;
        }
        close(fds[0]); _exit(0);
    }
    close(fds[0]);
    char *body = malloc(BODY_MAX); assert(body); memset(body, 'x', BODY_MAX);
    flags = fcntl(fds[1], F_GETFL);
    long long start = monotonic_ms();
    int rc = response(fds[1], 200, "OK", "text/plain", body, BODY_MAX);
    int saved_errno = errno;
    long long elapsed = monotonic_ms() - start;
    assert(rc == -1 && saved_errno == ETIMEDOUT);
    assert(elapsed >= D2K_PANEL_RESPONSE_TIMEOUT_MS && elapsed < 400);
    assert(fcntl(fds[1], F_GETFL) == flags);
    free(body); close(fds[1]);
    assert(kill(child, SIGTERM) == 0); assert(waitpid(child, NULL, 0) == child);
    puts("HTTP responses: complete response accepted; slow reader total deadline enforced PASS");
    return 0;
}
