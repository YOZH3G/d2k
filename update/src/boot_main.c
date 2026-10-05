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
  if (d2ku_service_recovery_context(&c, runtime) != D2KU_OK)
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
