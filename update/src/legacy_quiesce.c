#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../../runtime/d2k_runtime.h"
#include "legacy_runtime.h"
#include <dirent.h>
#include <errno.h>
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
d2ku_rc d2ku_legacy_before(d2ku_service_config *s, const char *action,
                           const char *id, uint64_t mask) {
  if (!stopping(action))
    return D2KU_OK;
  d2ku_rc rc = collect(s, id, 1);
  if (rc != D2KU_OK)
    return rc;
  /* Main runtimes flush through the platform stop. TERM old helper trees first
   * so they cannot resurrect writers while that stop is in progress. */
  for (size_t i = 0; i < s->legacy_writer_count; i++) {
    int runtime = 0;
    for (unsigned k = 0; k < 4; k++)
      if (d2ku_legacy_process(s, id, k, s->legacy_writers[i], 1))
        runtime = 1;
    if (!runtime && alive(s, i) && kill(s->legacy_writers[i], SIGTERM) &&
        errno != ESRCH)
      return D2KU_IO;
  }
  int log = openat(s->ctx->root_dirfd, "log",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (log >= 0) {
    s->legacy_log_fd =
        openat(log, "d2kc.log", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    close(log);
    if (s->legacy_log_fd >= 0) {
      struct stat st;
      if (fstat(s->legacy_log_fd, &st) || !S_ISREG(st.st_mode) ||
          st.st_uid != geteuid() || (st.st_mode & 022) || st.st_nlink != 1) {
        close(s->legacy_log_fd);
        s->legacy_log_fd = -1;
        return D2KU_INVALID;
      }
      s->legacy_log_offset = lseek(s->legacy_log_fd, 0, SEEK_END);
      if (s->legacy_log_offset < 0)
        return D2KU_IO;
    }
  }
  if ((mask & D2KU_SERVICE_CORE) && s->legacy_log_fd < 0)
    return D2KU_HEALTH;
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
    char b[65537];
    ssize_t n = read(s->legacy_log_fd, b, sizeof b - 1);
    if (n < 0 || n == (ssize_t)sizeof b - 1)
      rc = D2KU_HEALTH;
    else {
      b[n] = 0;
      if (strstr(b, "каталог не сохран") || strstr(b, "не сохранить каталог"))
        rc = D2KU_HEALTH;
    }
    close(s->legacy_log_fd);
    s->legacy_log_fd = -1;
  }
  s->legacy_writer_count = 0;
  return rc;
}
