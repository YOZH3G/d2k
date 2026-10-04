#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "transaction_internal.h"
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
int main(int argc, char **argv) {
  const char *root = "/opt/d2k", *runtime = NULL;
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
      (strcmp(argv[at], "--recover") && strcmp(argv[at], "--supervise") &&
       strcmp(argv[at], "--bootstrap") && strcmp(argv[at], "--daemon"))) {
    fprintf(stderr, "usage: d2k-update-boot [--root DIR] [--runtime DIR] "
                    "--recover | --supervise WORKER [ARGS...]\n");
    return 2;
  }
  d2ku_ctx c = {0};
  c.maintenance_lock_fd = -1;
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  c.health_runtime_dirfd = -1;
  c.bootstrap_prefix_fd = c.bootstrap_bundle_fd = -1;
  struct stat st;
  if (c.root_dirfd < 0 || fstat(c.root_dirfd, &st) || st.st_uid != geteuid() ||
      (st.st_mode & 022)) {
    fprintf(stderr, "invalid update root\n");
    return 1;
  }
  c.updater_version = 1;
  c.wire_version = 13;
  c.state_version = 1;
  c.clock.monotonic = mono;
  c.clock.snapshot = sample;
  d2ku_service_config config;
  d2ku_rc configured = d2ku_service_configure(&c, root, &config);
  if (configured != D2KU_OK) {
    fprintf(stderr,
            "unsupported managed configuration; writable personal paths must "
            "stay beneath root (result=%d)\n",
            configured);
    return 1;
  }
  if (!runtime)
    runtime = config.runtime;
  if (mkdir(runtime, 0700) && errno != EEXIST)
    return 1;
  c.health_runtime_dirfd =
      open(runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (c.health_runtime_dirfd < 0 || fstat(c.health_runtime_dirfd, &st) ||
      st.st_uid != geteuid() || (st.st_mode & 077))
    return 1;
  char prefix[1024];
  if (strlen(root) >= sizeof prefix)
    return 1;
  strcpy(prefix, root);
  char *slash = strrchr(prefix, '/');
  if (!slash || slash == prefix)
    return 1;
  *slash = 0;
  c.bootstrap_prefix_fd =
      open(prefix, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  d2ku_status s = {0};
  d2ku_rc r;
  int pending = fstatat(c.root_dirfd, "update-state/bootstrap.pending", &st,
                        AT_SYMLINK_NOFOLLOW) == 0;
  if (!strcmp(argv[at], "--bootstrap") || pending) {
    if (!strcmp(argv[at], "--bootstrap")) {
      if (at + 2 != argc)
        return 2;
      c.bootstrap_bundle_fd =
          open(argv[at + 1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    r = d2ku_bootstrap(&c, &s);
    if (r != D2KU_OK)
      goto done;
  }
  if (!strcmp(argv[at], "--recover"))
    r = at + 1 == argc ? d2ku_recover(&c, &s) : D2KU_INVALID;
  else if (!strcmp(argv[at], "--bootstrap"))
    r = D2KU_OK;
  else if (!strcmp(argv[at], "--daemon")) {
    r = d2ku_recover(&c, &s);
    char id[D2KU_ID_MAX + 1], worker[1200];
    if (r == D2KU_OK)
      r = d2ku_tx_current(&c, id);
    if (r == D2KU_OK) {
      snprintf(worker, sizeof worker, "%s/releases/%s/d2k-update", root, id);
      if (access(worker, X_OK)) {
        fprintf(stderr, "update daemon is unavailable\n");
        r = D2KU_ABSENT;
      } else {
        char *args[] = {worker, "--boot-worker", "3", NULL};
        r = d2ku_supervise(&c, worker, args, &s);
      }
    }
  } else
    r = at + 1 < argc ? d2ku_supervise(&c, argv[at + 1], &argv[at + 1], &s)
                      : D2KU_INVALID;
done:
  if (c.bootstrap_prefix_fd >= 0)
    close(c.bootstrap_prefix_fd);
  if (c.bootstrap_bundle_fd >= 0)
    close(c.bootstrap_bundle_fd);
  if (c.health_runtime_dirfd >= 0)
    close(c.health_runtime_dirfd);
  close(c.root_dirfd);
  if (r != D2KU_OK)
    fprintf(stderr, "update recovery result=%d\n", (int)r);
  return r == D2KU_OK ? 0 : 1;
}
