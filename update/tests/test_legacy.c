/* Private filesystem only: typed source anchoring, complete inventory
 * integrity, journal source kind and refusal to treat a signed receipt as
 * legacy. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../src/legacy.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static void put(int d, const char *name, const char *s) {
  int f = openat(d, name, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  assert(f >= 0);
  assert(write(f, s, strlen(s)) == (ssize_t)strlen(s));
  close(f);
}
static unsigned cut, barrier;
static d2ku_rc crash_sync(void *arg, int fd) {
  (void)arg;
  if (fsync(fd))
    return D2KU_IO;
  if (++barrier == cut)
    _exit(88);
  return D2KU_OK;
}
int main(void) {
  char root[] = "/tmp/d2ku-legacy.XXXXXX";
  assert(mkdtemp(root));
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  assert(c.root_dirfd >= 0);
  const char *dirs[] = {
      "update-state",       "update", "update/legacy-flat",      "releases",
      "releases/local-old", "files",  "releases/local-old/files"};
  for (unsigned i = 0; i < 7; i++)
    assert(!mkdirat(c.root_dirfd, dirs[i], 0700));
  int old = openat(c.root_dirfd, "update/legacy-flat", O_RDONLY | O_DIRECTORY),
      rel = openat(c.root_dirfd, "releases/local-old", O_RDONLY | O_DIRECTORY);
  assert(old >= 0 && rel >= 0);
  put(old, "d2kd", "original");
  put(rel, "d2kd", "original");
  put(c.root_dirfd, "files/asset", "resource");
  put(rel, "files/asset", "resource");
  unsigned char h[32], got[32];
  assert(d2ku_legacy_hash(old, h) == D2KU_OK);
  assert(d2ku_legacy_create(&c, old, rel, "local-old", "arm64", h) == D2KU_OK);
  assert(d2ku_legacy_source(&c, "local-old", got) == D2KU_OK &&
         !memcmp(h, got, 32));
  strcpy(c.abi, "mipsel");
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  strcpy(c.abi, "arm64");
  put(rel, "d2kd", "changed");
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  put(rel, "d2kd", "original");
  put(old, "extra-helper", "unsealed");
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  assert(!unlinkat(old, "extra-helper", 0));
  put(c.root_dirfd, "files/asset", "changed");
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  put(c.root_dirfd, "files/asset", "resource");
  assert(d2ku_legacy_source(&c, "local-old", got) == D2KU_OK);
  put(rel, ".d2ku-receipt", "D2KR1 13 1 1 counterfeit\n");
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  assert(!unlinkat(rel, ".d2ku-receipt", 0));
  assert(!symlinkat("d2kd", rel, "alias"));
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  assert(!unlinkat(rel, "alias", 0));
  assert(!linkat(rel, "d2kd", rel, "alias", 0));
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  assert(!unlinkat(rel, "alias", 0));
  assert(!fchmodat(rel, "files", 0755, 0));
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  assert(!fchmodat(rel, "files", 0700, 0));
  assert(d2ku_legacy_source(&c, "local-old", got) == D2KU_OK);
  /* Four durable barriers: receipt file/parent and anchor file/parent. A
   * restart reseals the same owner-authorized source before any execution. */
  for (unsigned stop = 1; stop <= 4; stop++) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
      c.sync_fd = crash_sync;
      cut = stop;
      barrier = 0;
      (void)d2ku_legacy_create(&c, old, rel, "local-old", "arm64", h);
      _exit(0);
    }
    int w;
    assert(waitpid(child, &w, 0) == child && WIFEXITED(w) &&
           WEXITSTATUS(w) == 88);
    assert(d2ku_legacy_create(&c, old, rel, "local-old", "arm64", h) ==
           D2KU_OK);
    assert(d2ku_legacy_source(&c, "local-old", got) == D2KU_OK);
  }
  put(c.root_dirfd, "update-state/legacy-source", "bad anchor");
  assert(d2ku_legacy_source(&c, "local-old", got) != D2KU_OK);
  d2ku_journal j = {.schema = 1,
                    .sequence = 1,
                    .phase = D2KU_PREPARED,
                    .command = D2KU_CMD_INSTALL,
                    .old_kind = D2KU_SOURCE_LEGACY_LOCAL};
  strcpy(j.transaction_id, "op");
  j.transaction_id_len = 2;
  strcpy(j.old_release_id, "local-old");
  j.old_release_id_len = 9;
  strcpy(j.new_release_id, "signed");
  j.new_release_id_len = 6;
  strcpy(j.progress_boot_id, "boot");
  j.progress_boot_id_len = 4;
  assert(d2ku_journal_store(&c, &j) == D2KU_OK);
  d2ku_journal loaded;
  assert(d2ku_journal_load(&c, &loaded) == D2KU_OK &&
         loaded.old_kind == D2KU_SOURCE_LEGACY_LOCAL &&
         loaded.command == D2KU_CMD_INSTALL);
  j.sequence++;
  j.old_kind = 7;
  assert(d2ku_journal_store(&c, &j) == D2KU_INVALID);
  close(old);
  close(rel);
  close(c.root_dirfd);
  char cmd[200];
  snprintf(cmd, sizeof cmd, "rm -rf %s", root);
  assert(!system(cmd));
  puts("legacy source: typed anchor, full saved/release/resources integrity, "
       "journal kind: PASS");
}
