/* Регрессия: отказ bind/listen в serve() не должен закрывать слушающий
 * дескриптор дважды. Настоящий main.c собирается с подменой close/bind/listen:
 * после первого закрытия сокета освободившийся номер занимает сторож
 * (/dev/null); второе close() того же номера уничтожило бы уже чужой файл.
 * Только частный каталог в /tmp, без сети и без служб. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fail_bind, fail_listen, listening = -1, sentinel = -1, binds, listens;
static int test_bind(int fd, const struct sockaddr *a, socklen_t n) {
  binds++;
  listening = fd;
  if (fail_bind) {
    errno = EADDRINUSE;
    return -1;
  }
  return bind(fd, a, n);
}
static int test_listen(int fd, int backlog) {
  listens++;
  if (fail_listen) {
    errno = EOPNOTSUPP;
    return -1;
  }
  return listen(fd, backlog);
}
static int test_close(int fd) {
  int r = close(fd);
  if (r == 0 && fd == listening && sentinel < 0) {
    /* Ровно тот же номер, даже если ниже есть свободные. */
    int s = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (s >= 0 && s != fd) {
      if (dup2(s, fd) == fd)
        sentinel = fd;
      close(s);
    } else if (s == fd)
      sentinel = s;
  }
  return r;
}

#define main d2ku_main
#define bind test_bind
#define listen test_listen
#define close test_close
#include "../src/main.c"
#undef close
#undef listen
#undef bind
#undef main

static void put(const char *root, const char *name, const char *text,
                mode_t mode) {
  char path[1400];
  snprintf(path, sizeof path, "%s/%s", root, name);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
  if (fd < 0 || write(fd, text, strlen(text)) != (ssize_t)strlen(text) ||
      close(fd)) {
    perror(path);
    exit(2);
  }
}
/* 0 — сторож цел; 1 — двойное закрытие; иное — фикстура не дошла до отказа. */
static int attempt(int bind_failure) {
  char root[1024] = "/tmp/d2ku-main-socket-XXXXXX", real[1024], path[1400],
       text[2400];
  if (!mkdtemp(root) || !realpath(root, real))
    return 2;
  static const char *dirs[] = {"boot", "run", "state", "releases"};
  for (size_t i = 0; i < 4; i++) {
    snprintf(path, sizeof path, "%s/%s", real, dirs[i]);
    if (mkdir(path, 0700))
      return 2;
  }
  snprintf(text, sizeof text, "MODE=off\nD2K_RUNTIME_DIR=%s/run\nSTATE_DIR=%s/state\n",
           real, real);
  put(real, "config", text, 0644);
  put(real, "boot/update.conf",
      "D2KU-CONFIG-1\nfeed=https://updates.invalid\nhost=updates.invalid\n"
      "ca=/nonexistent/fixture-ca\nabi=arm64\nbuild=4102444800\n"
      "key=0100000000000000000000000000000000000000000000000000000000000000"
      " 1 4102444801\n",
      0600);
  fflush(NULL);
  pid_t child = fork();
  if (child < 0)
    return 2;
  if (child == 0) {
    fail_bind = bind_failure;
    fail_listen = !bind_failure;
    char *argv[] = {"d2k-update", "--root", real, "serve", NULL};
    int result = d2ku_main(4, argv);
    if (result != 1 || binds != 1 || listens != !bind_failure || sentinel < 0)
      _exit(3); /* отказ не воспроизведён: тест ничего не доказал */
    struct stat a, b;
    if (fstat(sentinel, &a) || stat("/dev/null", &b) || a.st_rdev != b.st_rdev)
      _exit(1);
    _exit(0);
  }
  int status;
  if (waitpid(child, &status, 0) != child)
    return 2;
  snprintf(text, sizeof text, "rm -rf '%s'", real);
  if (system(text))
    return 2;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
int main(void) {
  int a = attempt(1), b = attempt(0);
  if (a || b) {
    fprintf(stderr,
            "main socket: bind-failure=%d listen-failure=%d "
            "(1 = listening fd closed twice, sentinel destroyed)\n",
            a, b);
    return 1;
  }
  puts("main socket: bind and listen failure close the listening fd exactly "
       "once: PASS");
  return 0;
}
