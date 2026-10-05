#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../../runtime/d2k_runtime.h"
#include "legacy_runtime.h"
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#include <signal.h>
#include <sys/wait.h>
static int index_of(d2ku_service_config *s, pid_t pid) {
  for (size_t i = 0; i < s->legacy_writer_count; i++)
    if (s->legacy_writers[i] == pid)
      return (int)i;
  return -1;
}
static int add(d2ku_service_config *s, pid_t pid) {
  char state;
  pid_t parent;
  uint64_t ticks = d2ku_legacy_ticks(pid, &state, &parent);
  if (!ticks || state == 'Z' || state == 'X')
    return 1;
  if (index_of(s, pid) >= 0)
    return 1;
  if (s->legacy_writer_count == 128)
    return 0;
  size_t i = s->legacy_writer_count++;
  s->legacy_writers[i] = pid;
  s->legacy_writer_ticks[i] = ticks;
  return 1;
}
static int alive(d2ku_service_config *s, size_t i) {
  char state;
  pid_t parent;
  uint64_t ticks = d2ku_legacy_ticks(s->legacy_writers[i], &state, &parent);
  if (!ticks || ticks != s->legacy_writer_ticks[i])
    return 0;
  if (state == 'Z' || state == 'X') {
    (void)waitpid(s->legacy_writers[i], NULL, WNOHANG);
    return 0;
  }
  return 1;
}
static int ancestor(pid_t pid) {
  pid_t p = getpid();
  for (unsigned i = 0; i < 64 && p > 1; i++) {
    if (p == pid)
      return 1;
    char state;
    pid_t parent;
    if (!d2ku_legacy_ticks(p, &state, &parent) || p == parent)
      break;
    p = parent;
  }
  return 0;
}
static int command(pid_t pid, char out[8192]) {
  char path[64];
  snprintf(path, sizeof path, "/proc/%ld/cmdline", (long)pid);
  int f = open(path, O_RDONLY | O_CLOEXEC);
  if (f < 0)
    return 0;
  ssize_t n = read(f, out, 8191);
  close(f);
  if (n <= 0)
    return 0;
  for (ssize_t i = 0; i < n; i++)
    if (!out[i])
      out[i] = ' ';
  out[n] = 0;
  return 1;
}
static int adapter_waiter(d2ku_service_config *s, pid_t pid) {
  char path[64], want[1200];
  snprintf(path, sizeof path, "/proc/%ld/exe", (long)pid);
  snprintf(want, sizeof want, "%s/boot/d2k-service-adapter", s->root);
  struct stat a, b;
  return !stat(path, &a) && !stat(want, &b) && a.st_dev == b.st_dev &&
         a.st_ino == b.st_ino;
}
/* Old loops and NDM invocations predate maintenance. Enumerate them and their
 * descendants before stopping; the lock alone cannot quiesce that population.
 */
static d2ku_rc collect(d2ku_service_config *s, const char *id, int reset) {
  const char *names[] = {"d2kd.pid",
                         "d2k.pid",
                         "d2k-panel.pid",
                         "d2ktg.pid",
                         "d2k-heal.pid",
                         "d2k-tg-watchdog.pid",
                         "d2k-instagram-dns-scheduler.pid",
                         "d2k-log-maintenance.pid"};
  if (reset)
    s->legacy_writer_count = 0;
  for (unsigned i = 0; i < 8; i++) {
    pid_t pid;
    int n = d2ku_legacy_pid(s, names[i], &pid);
    if (n < 0)
      return D2KU_INVALID;
    if (!n)
      continue;
    char state;
    pid_t parent;
    if (!d2ku_legacy_ticks(pid, &state, &parent) || state == 'Z')
      continue;
    if (i < 4 && !d2ku_legacy_process(s, id, i, pid, 1))
      return D2KU_HEALTH;
    if (i >= 4) {
      char cmd[8192];
      if (!command(pid, cmd) || !strstr(cmd, s->root))
        return D2KU_HEALTH;
    }
    if (!add(s, pid))
      return D2KU_INVALID;
  }
  for (unsigned pass = 0; pass < 128; pass++) {
    size_t before = s->legacy_writer_count;
    DIR *d = opendir("/proc");
    if (!d)
      return D2KU_INCOMPATIBLE;
    struct dirent *e;
    while ((e = readdir(d))) {
      char *end;
      long num = strtol(e->d_name, &end, 10);
      if (*end || num <= 1 || num > INT32_MAX)
        continue;
      pid_t pid = (pid_t)num;
      if (ancestor(pid))
        continue;
      char state;
      pid_t parent;
      if (!d2ku_legacy_ticks(pid, &state, &parent) || state == 'Z')
        continue;
      int child = index_of(s, parent) >= 0;
      /* Preserve independent lifecycle waiters, but quiesce a captured old
       * helper's blocked adapter child too: shells defer TERM while waiting
       * for that child, which cannot acquire the lock held by this stop. */
      if (!child && adapter_waiter(s, pid))
        continue;
      char cmd[8192];
      int has_command = command(pid, cmd);
      char ndm[1200], init[1200], prefix[1024];
      strcpy(prefix, s->root);
      char *slash = strrchr(prefix, '/');
      if (!slash) {
        closedir(d);
        return D2KU_INVALID;
      }
      *slash = 0;
      snprintf(ndm, sizeof ndm, "%s/etc/ndm/netfilter.d/001-d2k.sh", prefix);
      snprintf(init, sizeof init, "%s/etc/init.d/S99d2k", prefix);
      int entry = has_command && (strstr(cmd, ndm) || strstr(cmd, init));
      int own = has_command && (strstr(cmd, s->root) != NULL || entry);
      if (child) {
        if (!add(s, pid)) {
          closedir(d);
          return D2KU_INVALID;
        }
      } else if (own && index_of(s, pid) < 0) { /* Only historical known helper
                                                   role names may be adopted. */
        const char *helpers[] = {
            "d2k-fw-heal.sh",        "d2k-tg-firewall.sh",
            "d2k-tg-watchdog.sh",    "d2k-ppe-deoffload.sh",
            "d2k-instagram-dns.sh",  "d2k-instagram-dns-scheduler.sh",
            "d2k-log-maintenance.sh"};
        int known = entry;
        for (unsigned k = 0; k < 7; k++)
          if (strstr(cmd, helpers[k]))
            known = 1;
        if (!known || !add(s, pid)) {
          closedir(d);
          return D2KU_BUSY;
        }
      }
    }
    closedir(d);
    if (before == s->legacy_writer_count)
      return D2KU_OK;
  }
  return D2KU_BUSY;
}
static int stopping(const char *a) {
  return !strcmp(a, "stop") || !strcmp(a, "remove-rules") ||
         !strcmp(a, "uninstall");
}
/* Same per-file ceiling as the sealed legacy inventory; stream in 16 KiB. */
#define LEGACY_LOG_MAX (128 * 1024 * 1024)
static int log_identity(d2ku_service_config *s) {
  struct stat held, named;
  int dir = openat(s->ctx->root_dirfd, "log",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int ok =
      dir >= 0 && !fstat(s->legacy_log_fd, &held) &&
      !fstatat(dir, "d2kc.log", &named, AT_SYMLINK_NOFOLLOW) &&
      S_ISREG(held.st_mode) && S_ISREG(named.st_mode) &&
      held.st_uid == geteuid() && !(held.st_mode & 022) && held.st_nlink == 1 &&
      held.st_dev == named.st_dev && held.st_ino == named.st_ino &&
      held.st_size >= s->legacy_log_offset && held.st_size <= LEGACY_LOG_MAX;
  if (dir >= 0)
    close(dir);
  return ok;
}
static int log_owner(d2ku_service_config *s, pid_t core) {
  int index = index_of(s, core);
  if (index < 0 || !alive(s, (size_t)index))
    return 0;
  struct stat held, actual;
  if (fstat(s->legacy_log_fd, &held))
    return 0;
  /* Historical core redirects both stdout and stderr with freopen/dup2.
   * A pathname alone does not prove where its final save diagnostic goes. */
  for (unsigned fd = 1; fd <= 2; fd++) {
    char path[80];
    snprintf(path, sizeof path, "/proc/%ld/fd/%u", (long)core, fd);
    if (stat(path, &actual) || actual.st_dev != held.st_dev ||
        actual.st_ino != held.st_ino)
      return 0;
  }
  return alive(s, (size_t)index);
}
static int log_prefix(d2ku_service_config *s, unsigned char hash[32]) {
  if (s->legacy_log_offset < 0 || s->legacy_log_offset > LEGACY_LOG_MAX)
    return 0;
  EVP_MD_CTX *m = EVP_MD_CTX_new();
  if (!m)
    return 0;
  int ok = EVP_DigestInit_ex(m, EVP_sha256(), NULL);
  char b[16384];
  off_t at = 0;
  while (ok && at < s->legacy_log_offset) {
    off_t remaining = s->legacy_log_offset - at;
    size_t want = remaining < (off_t)sizeof b ? (size_t)remaining : sizeof b;
    ssize_t n = pread(s->legacy_log_fd, b, want, at);
    if (n <= 0) {
      ok = 0;
      break;
    }
    ok = EVP_DigestUpdate(m, b, (size_t)n);
    at += n;
  }
  unsigned len = 0;
  ok = ok && EVP_DigestFinal_ex(m, hash, &len) && len == 32;
  EVP_MD_CTX_free(m);
  return ok;
}
static d2ku_rc log_close(d2ku_service_config *s, d2ku_rc rc) {
  if (s->legacy_log_fd >= 0)
    close(s->legacy_log_fd);
  s->legacy_log_fd = -1;
  return rc;
}
d2ku_rc d2ku_legacy_before(d2ku_service_config *s, const char *action,
                           const char *id, uint64_t mask) {
  (void)mask;
  if (!stopping(action))
    return D2KU_OK;
  log_close(s, D2KU_OK);
  s->legacy_log_offset = 0;
  d2ku_rc rc = collect(s, id, 1);
  if (rc != D2KU_OK)
    return rc;
  pid_t core = 0;
  int runtime[128] = {0};
  for (size_t i = 0; i < s->legacy_writer_count; i++)
    for (unsigned k = 0; k < 4; k++)
      if (d2ku_legacy_process(s, id, k, s->legacy_writers[i], 1)) {
        runtime[i] = 1;
        if (k == 1)
          core = s->legacy_writers[i];
      }
  if (core) {
    int dir = openat(s->ctx->root_dirfd, "log",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir >= 0) {
      s->legacy_log_fd = openat(dir, "d2kc.log",
                                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
      close(dir);
    }
    if (s->legacy_log_fd < 0 || !log_identity(s) || !log_owner(s, core))
      return log_close(s, D2KU_HEALTH);
  }
  /* Main runtimes flush through platform stop. Old log-maintenance shells can
   * defer TERM while awaiting a child, so offset is fixed only after the entire
   * captured non-runtime population has exited. Timeout is not a clean stop. */
  for (size_t i = 0; i < s->legacy_writer_count; i++)
    if (!runtime[i] && alive(s, i) && kill(s->legacy_writers[i], SIGTERM) &&
        errno != ESRCH)
      return log_close(s, D2KU_IO);
  uint64_t start = d2k_runtime_mono_ms();
  int running;
  do {
    running = 0;
    for (size_t i = 0; i < s->legacy_writer_count; i++)
      if (!runtime[i] && alive(s, i))
        running = 1;
    if (!running)
      break;
    struct timespec delay = {0, 20000000};
    nanosleep(&delay, NULL);
  } while (d2k_runtime_mono_ms() - start < 3000);
  size_t captured = s->legacy_writer_count;
  if (running || collect(s, id, 0) != D2KU_OK ||
      captured != s->legacy_writer_count)
    return log_close(s, D2KU_HEALTH);
  if (core) {
    if (!log_identity(s) || !log_owner(s, core))
      return log_close(s, D2KU_HEALTH);
    s->legacy_log_offset = lseek(s->legacy_log_fd, 0, SEEK_END);
    if (s->legacy_log_offset < 0 || !log_prefix(s, s->legacy_log_prefix) ||
        !log_identity(s) || !log_owner(s, core))
      return log_close(s, D2KU_HEALTH);
  }
  return D2KU_OK;
}
d2ku_rc d2ku_legacy_after(d2ku_service_config *s, const char *action,
                          const char *id, uint64_t mask) {
  if (!strcmp(action, "start"))
    return d2ku_legacy_started(s, id, mask);
  (void)id;
  (void)mask;
  if (!stopping(action))
    return D2KU_OK;
  uint64_t start = d2k_runtime_mono_ms();
  int running = 1;
  while (running && d2k_runtime_mono_ms() - start < 3000) {
    running = 0;
    for (size_t i = 0; i < s->legacy_writer_count; i++)
      if (alive(s, i))
        running = 1;
    if (running) {
      struct timespec t = {0, 20000000};
      nanosleep(&t, NULL);
    }
  }
  size_t captured = s->legacy_writer_count;
  d2ku_rc scan = collect(s, id, 0);
  d2ku_rc rc = running || scan != D2KU_OK || captured != s->legacy_writer_count
                   ? D2KU_HEALTH
                   : D2KU_OK;
  if (s->legacy_log_fd >= 0) {
    unsigned char prefix[32];
    if (!log_identity(s) || !log_prefix(s, prefix) ||
        memcmp(prefix, s->legacy_log_prefix, sizeof prefix))
      rc = D2KU_HEALTH;
    char b[65537];
    ssize_t n = read(s->legacy_log_fd, b, sizeof b - 1);
    if (n < 0 || n == (ssize_t)sizeof b - 1)
      rc = D2KU_HEALTH;
    else {
      b[n] = 0;
      if (memchr(b, 0, (size_t)n) || strstr(b, "каталог не сохран") ||
          strstr(b, "не сохранить каталог") ||
          strstr(b, "кэш HTTPS не сохран") || strstr(b, "планы HTTP не сохран"))
        rc = D2KU_HEALTH;
    }
    if (!log_identity(s))
      rc = D2KU_HEALTH;
    log_close(s, D2KU_OK);
  }
  s->legacy_writer_count = 0;
  return rc;
}
