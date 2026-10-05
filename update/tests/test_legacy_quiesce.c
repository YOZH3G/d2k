/* Linux private process/filesystem fixture only. No network or service scripts.
 * The writer has real stdout/stderr FDs and a retained executable inode; its
 * exit-zero save-error behavior reproduces the historical controller contract.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "../src/legacy_runtime.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t quit;
static void stop(int sig) {
  (void)sig;
  quit = 1;
}
static void put(const char *p, const char *text) {
  int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  assert(fd >= 0);
  assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
  close(fd);
}
static void copy(const char *a, const char *b) {
  int in = open(a, O_RDONLY), out = open(b, O_WRONLY | O_CREAT | O_EXCL, 0700);
  assert(in >= 0 && out >= 0);
  char buf[16384];
  ssize_t n;
  while ((n = read(in, buf, sizeof buf)) > 0)
    assert(write(out, buf, (size_t)n) == n);
  assert(n == 0);
  close(in);
  close(out);
}
int main(int argc, char **argv) {
  assert(getenv("D2KU_LEGACY_LAB") && !strcmp(getenv("D2KU_LEGACY_LAB"), "1"));
  if (argc == 4 && !strcmp(argv[1], "writer")) {
    int f = open(argv[2], O_WRONLY | O_CREAT | O_APPEND, 0600);
    assert(f >= 0);
    assert(dup2(f, 1) == 1 && dup2(f, 2) == 2);
    close(f);
    signal(SIGTERM, stop);
    assert(write(1, "original diagnostic prefix\n", 27) == 27);
    while (!quit)
      pause();
    if (!strcmp(argv[3], "save-error"))
      dprintf(2, "d2kc: каталог не сохранён на выходе: fixture\n");
    return 0;
  }
  assert(argc == 2);
  const char *scenario = argv[1];
  char root[] = "/tmp/d2ku-quiesce-XXXXXX";
  assert(mkdtemp(root));
  char path[1200], log[1200], binary[1200], pidfile[1200];
  const char *dirs[] = {"run", "log", "state", "releases", "releases/fixture"};
  for (unsigned i = 0; i < 5; i++) {
    snprintf(path, sizeof path, "%s/%s", root, dirs[i]);
    assert(!mkdir(path, 0700));
  }
  snprintf(binary, sizeof binary, "%s/releases/fixture/d2kc", root);
  copy("/proc/self/exe", binary);
  snprintf(log, sizeof log, "%s/log/d2kc.log", root);
  snprintf(path, sizeof path, "%s/config", root);
  put(path, "MODE=observe\nTG_ENABLED=0\n");
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  assert(c.root_dirfd >= 0);
  d2ku_service_config s;
  assert(d2ku_service_configure(&c, root, &s) == D2KU_OK);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    execl(binary, binary, "writer", log, scenario, (char *)NULL);
    _exit(127);
  }
  snprintf(pidfile, sizeof pidfile, "%s/run/d2k.pid", root);
  char text[64];
  snprintf(text, sizeof text, "%ld\n", (long)child);
  put(pidfile, text);
  struct timespec tick = {0, 10000000};
  struct stat st;
  for (unsigned i = 0; i < 100 && (stat(log, &st) || st.st_size < 27); i++)
    nanosleep(&tick, NULL);
  assert(!stat(log, &st) && st.st_size == 27);
  pid_t helper = 0;
  if (!strcmp(scenario, "helper") || !strcmp(scenario, "helper-replace")) {
    snprintf(path, sizeof path, "%s/d2k-log-maintenance.sh", root);
    put(path, "#!/bin/sh\ntrap 'sleep .2; printf rotated\\\\n > \"$1\"; exit "
              "0' TERM\nwhile :; do sleep 1; done\n");
    if (!strcmp(scenario, "helper-replace"))
      put(path, "#!/bin/sh\ntrap 'mv \"$1\" \"$1.old\"; : > \"$1\"; exit 0' "
                "TERM\nwhile :; do sleep 1; done\n");
    helper = fork();
    assert(helper >= 0);
    if (!helper) {
      execl("/bin/sh", "sh", path, log, (char *)NULL);
      _exit(127);
    }
    snprintf(path, sizeof path, "%s/run/d2k-log-maintenance.pid", root);
    snprintf(text, sizeof text, "%ld\n", (long)helper);
    put(path, text);
    struct timespec pause = {0, 100000000};
    nanosleep(&pause, NULL);
  }
  if (!strcmp(scenario, "replaced-before")) {
    snprintf(path, sizeof path, "%s/log/old", root);
    assert(!rename(log, path));
    put(log, "");
  }
  if (!strcmp(scenario, "oversized")) {
    int f = open(log, O_WRONLY);
    assert(f >= 0);
    assert(!ftruncate(f, 128 * 1024 * 1024 + 1));
    close(f);
  }
  d2ku_rc pre = d2ku_legacy_before(&s, "stop", "fixture", D2KU_SERVICE_CORE);
  if (!strcmp(scenario, "replaced-before") ||
      !strcmp(scenario, "helper-replace") || !strcmp(scenario, "oversized")) {
    kill(child, SIGTERM);
    waitpid(child, NULL, 0);
    assert(pre == D2KU_HEALTH);
  } else {
    assert(pre == D2KU_OK);
    int helper_done = 1;
    if (helper) {
      int status;
      pid_t w = waitpid(helper, &status, WNOHANG);
      helper_done = w == helper || (w == -1 && errno == ECHILD);
    }
    kill(child, SIGTERM);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
    assert(helper_done); /* offset only after the helper has exited */
    if (!strcmp(scenario, "truncated"))
      put(log, "");
    if (!strcmp(scenario, "rewritten"))
      put(log, "modified diagnostic prefix\n");
    if (!strcmp(scenario, "replaced-after")) {
      snprintf(path, sizeof path, "%s/log/old", root);
      assert(!rename(log, path));
      put(log, "");
    }
    d2ku_rc after = d2ku_legacy_after(&s, "stop", "fixture", D2KU_SERVICE_CORE);
    int good = !strcmp(scenario, "normal") || !strcmp(scenario, "helper");
    assert(after == (good ? D2KU_OK : D2KU_HEALTH));
  }
  close(c.root_dirfd);
  snprintf(path, sizeof path, "rm -rf %s", root);
  assert(!system(path));
  printf("legacy diagnostic %s: PASS\n", scenario);
}
