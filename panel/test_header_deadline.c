#define _POSIX_C_SOURCE 200809L
#include "server.c"
#include <assert.h>
#include <sys/wait.h>

int main(void) {
    const char *header = "GET / HTTP/1.0\r\n\r\n";
    char buf[REQUEST_MAX + 1]; size_t used;
    int fds[2]; assert(pipe(fds) == 0);
    assert(write(fds[1], header, strlen(header)) == (ssize_t)strlen(header));
    assert(read_request(fds[0], buf, sizeof buf, &used) == 0);
    close(fds[0]); close(fds[1]);
    assert(pipe(fds) == 0);
    pid_t pid = fork(); assert(pid >= 0);
    if (!pid) {
        close(fds[0]); signal(SIGPIPE, SIG_IGN);
        struct timespec pause = { .tv_nsec = 20000000 };
        for (size_t i = 0; header[i]; ++i) {
            nanosleep(&pause, NULL);
            if (write(fds[1], header + i, 1) != 1) break;
        }
        close(fds[1]); _exit(0);
    }
    close(fds[1]);
    long long start = monotonic_ms();
    assert(read_request(fds[0], buf, sizeof buf, &used) == -1);
    assert(monotonic_ms() - start < 1000);
    close(fds[0]); assert(waitpid(pid, NULL, 0) == pid);
    puts("HTTP headers: complete request accepted; slow drip deadline enforced PASS");
    return 0;
}
