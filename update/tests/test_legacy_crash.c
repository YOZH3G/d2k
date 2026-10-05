/* Private filesystem / real historical offline CLI only. ROOT BUNDLE.
 * SIGKILL after each bootstrap durable callback; production resume must return
 * the complete typed inventory and never snapshot live personal data. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "../src/legacy.h"
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static unsigned barrier, cut;
static d2ku_rc sync_cut(void *p, int fd) {
  (void)p;
  if (fsync(fd))
    return D2KU_IO;
  if (++barrier == cut)
    kill(getpid(), SIGKILL);
  return D2KU_OK;
}
static void run(const char *exe, const char *a, const char *b, const char *c) {
  pid_t p = fork();
  assert(p >= 0);
  if (!p) {
    execlp(exe, exe, a, b, c, (char *)NULL);
    _exit(127);
  }
  int w;
  assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && !WEXITSTATUS(w));
}
static d2ku_rc bootstrap(const char *root, const char *prefix,
                         const char *bundle, int inject) {
  d2ku_ctx c = {.root_dirfd = open(root, O_RDONLY | O_DIRECTORY),
                .bootstrap_prefix_fd = open(prefix, O_RDONLY | O_DIRECTORY),
                .bootstrap_bundle_fd = open(bundle, O_RDONLY | O_DIRECTORY),
                .maintenance_lock_fd = -1,
                .health_runtime_dirfd = -1};
  d2ku_service_config sc;
  assert(c.root_dirfd >= 0 && c.bootstrap_prefix_fd >= 0 &&
         c.bootstrap_bundle_fd >= 0);
  assert(d2ku_service_configure(&c, root, &sc) == D2KU_OK);
  if (inject)
    c.sync_fd = sync_cut;
  d2ku_status s = {0};
  d2ku_rc rc = d2ku_bootstrap(&c, &s);
  if (rc != D2KU_OK)
    fprintf(stderr, "bootstrap fixture rc=%d barrier=%u cut=%u\n", rc, barrier,
            cut);
  if (rc == D2KU_OK) {
    char id[128] = {0};
    assert(readlinkat(c.root_dirfd, "current", id, sizeof id - 1) > 0);
    unsigned char h[32];
    d2ku_rc sealed = d2ku_legacy_source(&c, id + 9, h);
    if (sealed != D2KU_OK) {
      fprintf(stderr, "source rc=%d barrier=%u cut=%u id=%s\n", sealed, barrier,
              cut, id);
    }
    assert(sealed == D2KU_OK);
    assert(faccessat(c.root_dirfd, "update/legacy-personal", F_OK, 0));
  }
  close(c.root_dirfd);
  close(c.bootstrap_prefix_fd);
  close(c.bootstrap_bundle_fd);
  return rc;
}
int main(int argc, char **argv) {
  assert(argc == 3 && getenv("D2KU_LEGACY_LAB") &&
         !strncmp(argv[1], "/tmp/d2ku-wire12-", 17));
  char prefix[1024], saved[1100];
  assert(strlen(argv[1]) < sizeof prefix);
  strcpy(prefix, argv[1]);
  char *slash = strrchr(prefix, '/');
  assert(slash);
  *slash = 0;
  snprintf(saved, sizeof saved, "%s.saved", prefix);
  run("cp", "-a", prefix, saved);
  assert(bootstrap(argv[1], prefix, argv[2], 1) == D2KU_OK);
  unsigned total = barrier;
  for (unsigned k = 1; k <= total; k++) {
    run("rm", "-rf", prefix, NULL);
    run("cp", "-a", saved, prefix);
    fprintf(stderr, "checking barrier=%u/%u\n", k, total);
    pid_t p = fork();
    assert(p >= 0);
    if (!p) {
      barrier = 0;
      cut = k;
      (void)bootstrap(argv[1], prefix, argv[2], 1);
      _exit(99);
    }
    int w;
    assert(waitpid(p, &w, 0) == p && WIFSIGNALED(w) && WTERMSIG(w) == SIGKILL);
    assert(bootstrap(argv[1], prefix, argv[2], 0) == D2KU_OK);
  }
  run("rm", "-rf", saved, NULL);
  printf("historical bootstrap: %u SIGKILL/fsync barriers recovered typed "
         "inventory, no live snapshot: PASS\n",
         total);
  return 0;
}
