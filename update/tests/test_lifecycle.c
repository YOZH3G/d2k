#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../src/lifecycle.h"
#include "../src/startup.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static d2ku_rc sample(void *p, d2ku_clock_sample *s) {
  (void)p;
  memset(s, 0, sizeof *s);
  strcpy(s->boot_id, "fixture-boot");
  return D2KU_OK;
}
int main(void) {
  char root[] = "/tmp/d2ku-lifecycle-XXXXXX";
  assert(mkdtemp(root));
  d2ku_ctx c = {.root_dirfd = open(root, O_RDONLY | O_DIRECTORY),
                .maintenance_lock_fd = -1};
  c.clock.snapshot = sample;
  d2ku_lifecycle l;
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_ABSENT);
  assert(d2ku_lifecycle_intent(&c, "op", getpid()) != D2KU_OK);
  const char *names[] = {"daemon.lock", "supervisor.lock"};
  for (size_t i = 0; i < 2; i++) {
    int guard = -1, owner = -1;
    assert(d2ku_startup_claim(&c, names[i], &guard, &owner) == D2KU_OK);
    d2ku_maintenance_unlock(guard);
    assert(d2ku_maintenance_lock(&c, &c.maintenance_lock_fd) == D2KU_OK);
    assert(d2ku_lifecycle_quiesce(&c, root) == D2KU_BUSY);
    assert(d2ku_lifecycle_load(&c, &l) == D2KU_ABSENT);
    close(owner);
    close(c.maintenance_lock_fd); c.maintenance_lock_fd = -1;
  }
  /* Старт после загрузки: S99 boot-start держит maintenance те же секунды,
   * что и супервизор/демон стартуют. Временно занятая блокировка — повод
   * подождать, а не выйти навсегда с BUSY. */
  pid_t holder = fork();
  assert(holder >= 0);
  if (!holder) {
    int held = -1;
    if (d2ku_maintenance_lock(&c, &held) != D2KU_OK)
      _exit(1);
    struct timespec hold = {1, 500000000};
    nanosleep(&hold, NULL);
    d2ku_maintenance_unlock(held);
    _exit(0);
  }
  struct timespec settle = {0, 200000000};
  nanosleep(&settle, NULL);
  {
    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    int guard = -1, owner = -1;
    assert(d2ku_startup_claim(&c, "supervisor.lock", &guard, &owner) == D2KU_OK);
    clock_gettime(CLOCK_MONOTONIC, &after);
    assert(after.tv_sec - before.tv_sec >= 1);
    d2ku_maintenance_unlock(guard);
    close(owner);
  }
  int holder_status;
  assert(waitpid(holder, &holder_status, 0) == holder && WIFEXITED(holder_status) &&
         WEXITSTATUS(holder_status) == 0);
  assert(d2ku_maintenance_lock(&c, &c.maintenance_lock_fd) == D2KU_OK);
  assert(d2ku_lifecycle_quiesce(&c, root) == D2KU_OK);
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_OK && l.stopped);
  assert(!unlinkat(c.root_dirfd, "update-state/lifecycle", 0));
  assert(d2ku_lifecycle_intent(&c, "op", getpid()) == D2KU_OK);
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_OK && !l.stopped);
  assert(d2ku_lifecycle_ack(&c, getpid() + 1) != D2KU_OK);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    close(c.maintenance_lock_fd);
    c.maintenance_lock_fd = -1;
    _exit(d2ku_lifecycle_ack(&c, getppid()) == D2KU_OK ? 0 : 1);
  }
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_OK && l.stopped);
  assert(d2ku_lifecycle_quiesce(&c, root) == D2KU_OK);
  assert(!unlinkat(c.root_dirfd, "update-state/lifecycle", 0));
  child = fork();
  assert(child >= 0);
  if (!child)
    _exit(0);
  assert(waitpid(child, &status, 0) == child);
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_ABSENT);
  child = fork();
  assert(child >= 0);
  if (!child) {
    assert(d2ku_lifecycle_intent(&c, "interrupted-remover", getpid()) ==
           D2KU_OK);
    _exit(0);
  }
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         WEXITSTATUS(status) == 0);
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_OK && !l.stopped);
  assert(d2ku_lifecycle_quiesce(&c, root) == D2KU_OK);
  assert(d2ku_lifecycle_load(&c, &l) == D2KU_OK && l.stopped);
  close(c.maintenance_lock_fd);
  close(c.root_dirfd);
  char cmd[256];
  snprintf(cmd, sizeof cmd, "rm -rf %s", root);
  assert(!system(cmd));
  puts("lifecycle: held lock intent, bound worker, supervisor ack without lock "
       "deadlock: PASS");
}
