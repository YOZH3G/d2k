#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "lifecycle.h"
#include "d2k_update_ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
static int valid(const char *s) {
  return *s && strlen(s) <= 64 &&
         strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
                   "789._-") == strlen(s);
}
static int seal(const char *p, size_t n, char out[65]) {
  unsigned char digest[32];
  unsigned len;
  if (EVP_Digest(p, n, digest, &len, EVP_sha256(), NULL) != 1 || len != 32)
    return 0;
  for (size_t k = 0; k < 32; k++)
    snprintf(out + k * 2, 3, "%02x", digest[k]);
  return 1;
}
static int encode(const d2ku_lifecycle *l, char b[384]) {
  int n = snprintf(b, 384, "D2KL1 %d %ld %s %s", l->stopped, (long)l->worker,
                   l->boot, l->operation);
  char hash[65];
  if (n < 0 || n >= 300 || !seal(b, (size_t)n, hash))
    return -1;
  return n + snprintf(b + n, 384 - (size_t)n, " %s\n", hash);
}
static d2ku_rc terminal(d2ku_ctx *c) {
  d2ku_journal j;
  d2ku_rc r = d2ku_journal_load(c, &j);
  return r == D2KU_ABSENT                                           ? D2KU_OK
         : r != D2KU_OK                                             ? r
         : j.phase == D2KU_COMMITTED || j.phase == D2KU_ROLLED_BACK ? D2KU_OK
                                                                    : D2KU_BUSY;
}
d2ku_rc d2ku_lifecycle_load(d2ku_ctx *c, d2ku_lifecycle *out) {
  int dir = openat(c->root_dirfd, "update-state",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  int fd = openat(dir, "lifecycle", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  close(dir);
  if (fd < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  struct stat st;
  char b[384], canonical[384], hash[65], extra;
  d2ku_lifecycle l = {0};
  long pid;
  ssize_t n;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_nlink != 1 || st.st_size <= 0 ||
      st.st_size > 383 || (n = read(fd, b, sizeof b - 1)) != st.st_size) {
    close(fd);
    return D2KU_RECOVERY;
  }
  close(fd);
  b[n] = 0;
  if (sscanf(b, "D2KL1 %d %ld %64s %64s %64s %c", &l.stopped, &pid, l.boot,
             l.operation, hash, &extra) != 5 ||
      (l.stopped != 0 && l.stopped != 1) || pid <= 1 || pid > INT32_MAX ||
      !valid(l.boot) || !valid(l.operation))
    return D2KU_RECOVERY;
  l.worker = (pid_t)pid;
  int len = encode(&l, canonical);
  if (len != n || memcmp(b, canonical, (size_t)n))
    return D2KU_RECOVERY;
  *out = l;
  return D2KU_OK;
}
static d2ku_rc store(d2ku_ctx *c, const d2ku_lifecycle *l) {
  int dir = openat(c->root_dirfd, "update-state",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir < 0)
    return D2KU_IO;
  char b[384];
  int n = encode(l, b);
  if (n < 0) {
    close(dir);
    return D2KU_IO;
  }
  unlinkat(dir, "lifecycle.new", 0);
  int fd = openat(dir, "lifecycle.new",
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  d2ku_rc r = D2KU_IO;
  if (fd >= 0 && write(fd, b, (size_t)n) == n && !fsync(fd) &&
      !renameat(dir, "lifecycle.new", dir, "lifecycle") && !fsync(dir))
    r = D2KU_OK;
  if (fd >= 0)
    close(fd);
  close(dir);
  return r;
}
d2ku_rc d2ku_lifecycle_intent(d2ku_ctx *c, const char *op, pid_t worker) {
  if (!valid(op) || worker <= 1 ||
      d2ku_service_lock_valid(c, c->maintenance_lock_fd) != D2KU_OK)
    return D2KU_INVALID;
  d2ku_rc r = terminal(c);
  if (r != D2KU_OK)
    return r;
  d2ku_lifecycle old;
  r = d2ku_lifecycle_load(c, &old);
  if (r != D2KU_ABSENT)
    return r == D2KU_OK ? D2KU_BUSY : r;
  d2ku_clock_sample now = {0};
  if (!c->clock.snapshot || c->clock.snapshot(c->clock.arg, &now) != D2KU_OK ||
      !valid(now.boot_id))
    return D2KU_TIME;
  d2ku_lifecycle l = {.worker = worker};
  strcpy(l.boot, now.boot_id);
  strcpy(l.operation, op);
  return store(c, &l);
}
d2ku_rc d2ku_lifecycle_ack(d2ku_ctx *c, pid_t worker) {
  d2ku_lifecycle l;
  d2ku_rc r = d2ku_lifecycle_load(c, &l);
  if (r != D2KU_OK)
    return r;
  d2ku_clock_sample now = {0};
  if (l.worker != worker || !c->clock.snapshot ||
      c->clock.snapshot(c->clock.arg, &now) != D2KU_OK ||
      strcmp(now.boot_id, l.boot))
    return D2KU_INVALID;
  r = terminal(c);
  if (r != D2KU_OK)
    return r;
  /* The remover still owns maintenance. It cannot remove code until this
   * acknowledgement is durable and supervisor.lock is released. Reacquiring
   * maintenance here would deadlock the handshake. No new intent can race:
   * all lifecycle entrypoints refuse the existing durable marker. */
  l.stopped = 1;
  return store(c, &l);
}
static int idle_lock(d2ku_ctx *c, const char *name) {
  char path[128];
  snprintf(path, sizeof path, "update-state/%s", name);
  int fd = openat(c->root_dirfd, path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT ? 1 : 0;
  struct stat st;
  int idle = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
             !(st.st_mode & 077) && !flock(fd, LOCK_EX | LOCK_NB);
  close(fd);
  return idle;
}
d2ku_rc d2ku_lifecycle_quiesce(d2ku_ctx *c, const char *root) {
  if (d2ku_service_lock_valid(c, c->maintenance_lock_fd) != D2KU_OK)
    return D2KU_INVALID;
  d2ku_lifecycle l;
  d2ku_rc r = d2ku_lifecycle_load(c, &l);
  if (r != D2KU_OK && r != D2KU_ABSENT)
    return r;
  char socket_path[1200];
  snprintf(socket_path, sizeof socket_path, "%s/update-state/updater.sock",
           root);
  if (r == D2KU_ABSENT) {
    int fd = d2ku_ipc_connect(socket_path);
    if (fd < 0) {
      if (!idle_lock(c, "daemon.lock") || !idle_lock(c, "supervisor.lock"))
        return D2KU_BUSY;
      /* Even a stopped installation must leave durable removal intent before
       * code deletion, so a delayed boot cannot start a new worker. */
      char operation[65];
      snprintf(operation, sizeof operation, "uninstall-%ld", (long)getpid());
      r = d2ku_lifecycle_intent(c, operation, getpid());
      return r == D2KU_OK ? d2ku_lifecycle_ack(c, getpid()) : r;
    }
    d2ku_command cmd = {.op = D2KU_CMD_QUIESCE};
    int code;
    char json[256];
    int fail = d2ku_ipc_exchange_lock(fd, &cmd, c->maintenance_lock_fd, &code,
                                      json, sizeof json);
    close(fd);
    if (fail || code != 202)
      return D2KU_BUSY;
  }
  for (unsigned i = 0; i < 100; i++) {
    r = d2ku_lifecycle_load(c, &l);
    if (r != D2KU_OK)
      return r;
    if (l.stopped && idle_lock(c, "daemon.lock") &&
        idle_lock(c, "supervisor.lock"))
      return terminal(c);
    /* A remover may have died after intent. A restarted remover can finish only
     * after both owned processes are gone; it never revives the updater. */
    if (idle_lock(c, "daemon.lock") && idle_lock(c, "supervisor.lock")) {
      r = terminal(c);
      if (r != D2KU_OK)
        return r;
      l.stopped = 1;
      return store(c, &l);
    }
    struct timespec t = {0, 100000000};
    nanosleep(&t, NULL);
  }
  return D2KU_BUSY;
}
