#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_update.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static unsigned barrier, cut;
static int reject_inventory;
static d2ku_rc offline(void *arg, int fd, const char *id) {
  (void)arg;
  (void)fd;
  (void)id;
  return reject_inventory ? D2KU_INCOMPATIBLE : D2KU_OK;
}
static d2ku_rc sync_cb(void *a, int fd) {
  (void)a;
  if (fsync(fd))
    return D2KU_IO;
  if (++barrier == cut)
    _exit(88);
  return D2KU_OK;
}
static d2ku_rc capture(void *a, uint64_t *n) {
  (void)a;
  *n = 4;
  return D2KU_OK;
}
static d2ku_rc services(void *a, const char *act, const char *id, uint64_t n) {
  (void)a;
  assert(n == 4);
  assert(id && !strncmp(id, "legacy-", 7));
  assert(!strcmp(act, "start") || !strcmp(act, "stop"));
  return D2KU_OK;
}
static void put(int at, const char *name, const char *data) {
  int fd = openat(at, name, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  assert(fd >= 0);
  assert(write(fd, data, strlen(data)) == (ssize_t)strlen(data));
  close(fd);
}
static void setup(d2ku_ctx *c, char root[64]) {
  strcpy(root, "/tmp/d2ku-bootstrap.XXXXXX");
  assert(mkdtemp(root));
  c->root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  assert(c->root_dirfd >= 0);
  assert(!mkdirat(c->root_dirfd, "prefix", 0700));
  c->bootstrap_prefix_fd =
      openat(c->root_dirfd, "prefix", O_RDONLY | O_DIRECTORY);
  assert(!mkdirat(c->root_dirfd, "bundle", 0700));
  c->bootstrap_bundle_fd =
      openat(c->root_dirfd, "bundle", O_RDONLY | O_DIRECTORY);
  const char *dirs[] = {"sbin", "etc", "etc/init.d", "etc/ndm",
                        "etc/ndm/netfilter.d"};
  for (unsigned i = 0; i < 5; i++)
    assert(!mkdirat(c->bootstrap_prefix_fd, dirs[i], 0700));
  const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
  for (unsigned i = 0; i < 4; i++) {
    char p[64];
    snprintf(p, sizeof p, "sbin/%s", bins[i]);
    put(c->bootstrap_prefix_fd, p, "legacy runtime\n");
  }
  put(c->bootstrap_prefix_fd, "etc/init.d/S99d2k", "legacy init\n");
  put(c->bootstrap_prefix_fd, "etc/ndm/netfilter.d/001-d2k.sh", "legacy ndm\n");
  const char *helpers[] = {
      "d2k-fw-heal.sh",        "d2k-tg-firewall.sh",
      "d2k-tg-watchdog.sh",    "d2k-ppe-deoffload.sh",
      "d2k-instagram-dns.sh",  "d2k-instagram-dns-scheduler.sh",
      "d2k-log-maintenance.sh"};
  for (unsigned i = 0; i < 7; i++) {
    put(c->root_dirfd, helpers[i], "legacy helper\n");
    put(c->bootstrap_bundle_fd, helpers[i], "managed helper\n");
  }
  assert(!mkdirat(c->root_dirfd, "panel", 0700));
  put(c->root_dirfd, "panel/index.html", "legacy panel\n");
  assert(!mkdirat(c->root_dirfd, "files", 0700));
  put(c->root_dirfd, "files/tg-roots.pem", "legacy trust\n");
  put(c->root_dirfd, "config", "private configuration\n");
  assert(!mkdirat(c->root_dirfd, "state", 0700));
  put(c->root_dirfd, "state/catalog.json", "learned state\n");
  put(c->root_dirfd, "state/tg.identity", "personal identity\n");
  const char *bundle[] = {"d2k-update-boot", "d2k-service-adapter",
                          "S99d2k",          "S98d2k-update",
                          "001-d2k.sh",      "uninstall.sh"};
  for (unsigned i = 0; i < 6; i++)
    put(c->bootstrap_bundle_fd, bundle[i], "trusted local bootstrap file\n");
  c->wire_version = 13;
  c->state_version = 1;
  c->updater_version = 1;
  c->maintenance_lock_fd = -1;
  c->sync_fd = sync_cb;
  c->transaction.offline = offline;
  c->transaction.capture = capture;
  c->transaction.services = services;
}
static void verify(d2ku_ctx *c) {
  char b[512] = {0};
  int f = openat(c->root_dirfd, "config", O_RDONLY);
  assert(read(f, b, sizeof b) > 0 && !strcmp(b, "private configuration\n"));
  close(f);
  f = openat(c->root_dirfd, "state/catalog.json", O_RDONLY);
  memset(b, 0, sizeof b);
  assert(read(f, b, sizeof b) > 0 && !strcmp(b, "learned state\n"));
  close(f);
  f = openat(c->root_dirfd, "state/tg.identity", O_RDONLY);
  memset(b, 0, sizeof b);
  assert(read(f, b, sizeof b) > 0 && !strcmp(b, "personal identity\n"));
  close(f);
  ssize_t n = readlinkat(c->root_dirfd, "current", b, sizeof b - 1);
  assert(n > 0);
  b[n] = 0;
  assert(!strncmp(b, "releases/legacy-", 16));
}
static void clean(d2ku_ctx *c, const char *root) {
  close(c->bootstrap_prefix_fd);
  close(c->bootstrap_bundle_fd);
  close(c->root_dirfd);
  char cmd[100];
  snprintf(cmd, sizeof cmd, "rm -rf %s", root);
  assert(!system(cmd));
}
int main(void) {
  char root[64];
  d2ku_ctx c = {0};
  d2ku_status s = {0};
  setup(&c, root);
  reject_inventory = 1;
  assert(d2ku_bootstrap(&c, &s) == D2KU_INCOMPATIBLE);
  struct stat absent;
  assert(fstatat(c.root_dirfd, "current", &absent, AT_SYMLINK_NOFOLLOW) < 0 &&
         errno == ENOENT);
  reject_inventory = 0;
  put(c.root_dirfd, "protected", "do not truncate\n");
  assert(!linkat(c.root_dirfd, "protected", c.root_dirfd,
                 "update/legacy-flat/.bootstrap-d2kd", 0));
  (void)d2ku_bootstrap(&c, &s);
  int protected_fd = openat(c.root_dirfd, "protected", O_RDONLY);
  char protected_bytes[64] = {0};
  assert(read(protected_fd, protected_bytes, sizeof protected_bytes) > 0);
  close(protected_fd);
  assert(!strcmp(protected_bytes, "do not truncate\n"));
  clean(&c, root);
  memset(&c, 0, sizeof c);
  setup(&c, root);
  barrier = 0;
  assert(d2ku_bootstrap(&c, &s) == D2KU_OK);
  unsigned count = barrier;
  verify(&c);
  assert(d2ku_bootstrap(&c, &s) == D2KU_OK);
  int record = openat(c.root_dirfd, "update-state/bootstrap.done", O_RDWR);
  assert(record >= 0);
  char record_bytes[512] = {0};
  ssize_t len = read(record, record_bytes, sizeof record_bytes - 1);
  assert(len > 0);
  char *mask = strstr(record_bytes, " 4");
  assert(mask);
  mask[1] = '0';
  assert(lseek(record, 0, SEEK_SET) == 0);
  assert(write(record, record_bytes, (size_t)len) == len);
  close(record);
  assert(d2ku_bootstrap(&c, &s) == D2KU_RECOVERY);
  clean(&c, root);
  for (unsigned i = 1; i <= count; i++) {
    memset(&c, 0, sizeof c);
    setup(&c, root);
    pid_t p = fork();
    assert(p >= 0);
    if (!p) {
      barrier = 0;
      cut = i;
      (void)d2ku_bootstrap(&c, &s);
      _exit(0);
    }
    int w;
    assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && WEXITSTATUS(w) == 88);
    cut = 0;
    assert(d2ku_bootstrap(&c, &s) == D2KU_OK);
    verify(&c);
    clean(&c, root);
  }
  printf("bootstrap personal data/disabled mask and %u crash barriers: PASS\n",
         count);
  return 0;
}
