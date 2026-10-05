#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../../runtime/d2k_runtime.h"
#include "legacy_runtime.h"
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
static const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
int d2ku_legacy_pid(d2ku_service_config *s, const char *name, pid_t *pid) {
  char path[128], b[40] = {0};
  snprintf(path, sizeof path, "run/%s", name);
  int f = openat(s->ctx->root_dirfd, path,
                 O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (f < 0)
    return errno == ENOENT ? 0 : -1;
  struct stat st;
  ssize_t n = -1;
  if (!fstat(f, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
      !(st.st_mode & 022) && st.st_nlink == 1)
    n = read(f, b, sizeof b - 1);
  close(f);
  char *end;
  long v = strtol(b, &end, 10);
  if (n <= 0 || v <= 1 || v > INT32_MAX || (*end && strcmp(end, "\n")))
    return -1;
  *pid = (pid_t)v;
  return 1;
}
uint64_t d2ku_legacy_ticks(pid_t pid, char *state, pid_t *parent) {
  char path[64], b[4096];
  snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;
  char *got = fgets(b, sizeof b, f);
  fclose(f);
  if (!got)
    return 0;
  char *p = strrchr(b, ')');
  if (!p)
    return 0;
  long par;
  if (sscanf(p + 1, " %c %ld", state, &par) != 2)
    return 0;
  *parent = (pid_t)par;
  return d2k_runtime_start_ticks(path);
}
static int filehash(int f, unsigned char h[32]) {
  EVP_MD_CTX *m = EVP_MD_CTX_new();
  if (!m)
    return 0;
  int ok = EVP_DigestInit_ex(m, EVP_sha256(), NULL);
  char b[16384];
  ssize_t n = 0;
  while (ok && (n = read(f, b, sizeof b)) > 0)
    ok = EVP_DigestUpdate(m, b, (size_t)n);
  unsigned size = 0;
  ok = ok && n == 0 && EVP_DigestFinal_ex(m, h, &size) && size == 32;
  EVP_MD_CTX_free(m);
  return ok;
}
int d2ku_legacy_process(d2ku_service_config *s, const char *id,
                        unsigned service, pid_t pid, int allow_flat) {
  char proc[64], path[256];
  snprintf(proc, sizeof proc, "/proc/%ld/exe", (long)pid);
  snprintf(path, sizeof path, "releases/%s/%s", id, bins[service]);
  int expected =
          openat(s->ctx->root_dirfd, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC),
      actual = open(proc, O_RDONLY | O_CLOEXEC);
  struct stat a, b;
  int ok = expected >= 0 && actual >= 0 && !fstat(expected, &a) &&
           !fstat(actual, &b) && S_ISREG(a.st_mode) && S_ISREG(b.st_mode) &&
           a.st_uid == geteuid() && b.st_uid == geteuid() &&
           !(a.st_mode & 022) && !(b.st_mode & 022);
  if (ok && (a.st_dev != b.st_dev || a.st_ino != b.st_ino)) {
    unsigned char x[32], y[32];
    ok = allow_flat && a.st_size == b.st_size && filehash(expected, x) &&
         filehash(actual, y) && !memcmp(x, y, 32);
  }
  if (expected >= 0)
    close(expected);
  if (actual >= 0)
    close(actual);
  char state;
  pid_t parent;
  return ok && d2ku_legacy_ticks(pid, &state, &parent) && state != 'Z' &&
         state != 'T' && state != 't' && state != 'X';
}
int d2ku_legacy_socket_owner(pid_t pid, unsigned long inode) {
  char path[80], want[80];
  snprintf(path, sizeof path, "/proc/%ld/fd", (long)pid);
  snprintf(want, sizeof want, "socket:[%lu]", inode);
  DIR *d = opendir(path);
  if (!d)
    return 0;
  struct dirent *e;
  int yes = 0;
  while ((e = readdir(d))) {
    char link[80];
    ssize_t n = readlinkat(dirfd(d), e->d_name, link, sizeof link - 1);
    if (n > 0) {
      link[n] = 0;
      if (!strcmp(link, want)) {
        yes = 1;
        break;
      }
    }
  }
  closedir(d);
  return yes;
}
static int listener(pid_t pid, uint16_t port) {
  const char *paths[] = {"/proc/net/tcp", "/proc/net/tcp6"};
  for (unsigned k = 0; k < 2; k++) {
    FILE *f = fopen(paths[k], "r");
    if (!f)
      continue;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
      char *save = NULL, *parts[12];
      unsigned n = 0;
      for (char *p = strtok_r(line, " \t\n", &save); p && n < 12;
           p = strtok_r(NULL, " \t\n", &save))
        parts[n++] = p;
      if (n < 10 || strcmp(parts[3], "0A"))
        continue;
      char *colon = strchr(parts[1], ':');
      if (!colon || strtoul(colon + 1, NULL, 16) != port)
        continue;
      unsigned long inode = strtoul(parts[9], NULL, 10);
      if (inode && d2ku_legacy_socket_owner(pid, inode)) {
        fclose(f);
        return 1;
      }
    }
    fclose(f);
  }
  return 0;
}
static int queue_owner(pid_t pid, uint16_t queue) {
  FILE *f = fopen("/proc/net/netfilter/nfnetlink_queue", "r");
  if (!f)
    return 0;
  char line[512];
  unsigned q;
  unsigned long port = 0, p;
  while (fgets(line, sizeof line, f))
    if (sscanf(line, "%u %lu", &q, &p) == 2 && q == queue) {
      port = p;
      break;
    }
  fclose(f);
  if (!port)
    return 0;
  f = fopen("/proc/net/netlink", "r");
  if (!f)
    return 0;
  int ok = 0;
  while (fgets(line, sizeof line, f)) {
    char *save = NULL, *part[12];
    unsigned n = 0;
    for (char *x = strtok_r(line, " \t\n", &save); x && n < 12;
         x = strtok_r(NULL, " \t\n", &save))
      part[n++] = x;
    if (n >= 10 && strtoul(part[1], NULL, 10) == 12 &&
        strtoul(part[2], NULL, 10) == port &&
        d2ku_legacy_socket_owner(pid, strtoul(part[9], NULL, 10))) {
      ok = 1;
      break;
    }
  }
  fclose(f);
  return ok;
}
d2ku_rc d2ku_legacy_greet(d2ku_service_config *s, const char *id) {
  pid_t dp = 0, core = 0;
  if (d2ku_legacy_pid(s, "d2kd.pid", &dp) != 1 ||
      !d2ku_legacy_process(s, id, 0, dp, 0))
    return D2KU_HEALTH;
  if (d2ku_legacy_pid(s, "d2k.pid", &core) == 1 && !kill(core, 0))
    return D2KU_BUSY;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return D2KU_IO;
  struct sockaddr_un a;
  memset(&a, 0, sizeof a);
  a.sun_family = AF_UNIX;
  if (snprintf(a.sun_path, sizeof a.sun_path, "%s/run/d2kd.sock", s->root) >=
      (int)sizeof a.sun_path) {
    close(fd);
    return D2KU_INVALID;
  }
  int fl = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  int ok = !connect(fd, (void *)&a, sizeof a) || errno == EINPROGRESS;
#ifdef __linux__
  struct {
    pid_t pid;
    uid_t uid;
    gid_t gid;
  } peer;
  socklen_t len = sizeof peer;
  if (ok && (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &len) ||
             peer.pid != dp || peer.uid != geteuid()))
    ok = 0;
#else
  ok = 0;
#endif
  unsigned char frame[50];
  size_t used = 0;
  uint64_t start = d2k_runtime_mono_ms();
  while (ok && used < sizeof frame && d2k_runtime_mono_ms() - start < 2000) {
    struct pollfd pfd = {fd, POLLIN, 0};
    if (poll(&pfd, 1, 50) != 1)
      continue;
    ssize_t n = read(fd, frame + used, sizeof frame - used);
    if (n > 0)
      used += (size_t)n;
    else if (!n || (errno != EAGAIN && errno != EINTR)) {
      ok = 0;
      break;
    }
  }
  close(fd);
  return ok && used == 50 && frame[0] == 0 && frame[1] == 0 && frame[2] == 0 &&
                 frame[3] == 46 && frame[4] == 0 && frame[5] == 10 &&
                 frame[44] == 0 && frame[45] == 12
             ? D2KU_OK
             : D2KU_HEALTH;
}
static int live(d2ku_ctx *c, uint64_t *token) {
  int f = openat(c->health_runtime_dirfd, "live.json",
                 O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (f < 0)
    return 0;
  struct stat s;
  char b[128] = {0};
  int ok = !fstat(f, &s) && S_ISREG(s.st_mode) && s.st_uid == geteuid() &&
           !(s.st_mode & 022) && s.st_nlink == 1 &&
           read(f, b, sizeof b - 1) > 0 && strstr(b, "\"linked\": true");
  close(f);
  if (ok) {
#ifdef __APPLE__
    *token = (uint64_t)s.st_ino ^ (uint64_t)s.st_mtimespec.tv_nsec ^
             ((uint64_t)s.st_mtime << 32);
#else
    *token = (uint64_t)s.st_ino ^ (uint64_t)s.st_mtim.tv_nsec ^
             ((uint64_t)s.st_mtime << 32);
#endif
  }
  return ok;
}
static int stats(d2ku_ctx *c, pid_t pid, uint64_t *elapsed) {
  int log = openat(c->root_dirfd, "log",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (log < 0)
    return 0;
  int f =
      openat(log, "d2kd.log", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  close(log);
  if (f < 0)
    return 0;
  struct stat st;
  char b[32769];
  int ok = !fstat(f, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
           !(st.st_mode & 022) && st.st_nlink == 1;
  if (ok && st.st_size > 32768)
    ok = lseek(f, st.st_size - 32768, SEEK_SET) >= 0;
  ssize_t n = ok ? read(f, b, sizeof b - 1) : -1;
  close(f);
  if (n <= 0)
    return 0;
  b[n] = 0;
  char needle[64];
  snprintf(needle, sizeof needle, "--- d2kd[%ld], ", (long)pid);
  char *p = b, *last = NULL;
  while ((p = strstr(p, needle))) {
    last = p;
    p++;
  }
  if (!last)
    return 0;
  char *end;
  unsigned long long v = strtoull(last + strlen(needle), &end, 10);
  if (end == last + strlen(needle) || strncmp(end, " с;", strlen(" с;")))
    return 0;
  *elapsed = v;
  return 1;
}
static int telegram_state(d2ku_service_config *sc) {
  int f = openat(sc->ctx->root_dirfd, sc->ctx->health_state_paths[2],
                 O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (f < 0)
    return 0;
  char b[32] = {0};
  struct stat st;
  ssize_t n =
      (!fstat(f, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
       !(st.st_mode & 022) && st.st_nlink == 1)
          ? read(f, b, sizeof b - 1)
          : -1;
  close(f);
  return n > 0 && (!strcmp(b, "connecting\n") || !strcmp(b, "connected\n"));
}
/* start-stop-daemon publishes a PID before exec/readiness. Bound that startup
 * interval separately; the required 120-second observation starts afterwards.
 */
d2ku_rc d2ku_legacy_started(d2ku_service_config *sc, const char *id,
                            uint64_t mask) {
  const char *names[] = {"d2kd.pid", "d2k.pid", "d2k-panel.pid", "d2ktg.pid"};
  d2ku_ctx local = *sc->ctx;
  local.health_runtime_dirfd =
      open(sc->runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (local.health_runtime_dirfd < 0)
    return D2KU_HEALTH;
  uint64_t start = d2k_runtime_mono_ms();
  int ok = 0;
  do {
    ok = 1;
    pid_t pid[4] = {0};
    for (unsigned i = 0; i < 4; i++)
      if (mask & (UINT64_C(1) << i))
        if (d2ku_legacy_pid(sc, names[i], &pid[i]) != 1 ||
            !d2ku_legacy_process(sc, id, i, pid[i], 0))
          ok = 0;
    uint64_t token, elapsed;
    if ((mask & 3) &&
        (!queue_owner(pid[0], local.health_queue) || !live(&local, &token) ||
         !stats(&local, pid[0], &elapsed) || !elapsed))
      ok = 0;
    if ((mask & 4) && !listener(pid[2], local.health_panel_port))
      ok = 0;
    if ((mask & 8) && !listener(pid[3], sc->tg_port))
      ok = 0;
    if (ok)
      break;
    struct timespec pause = {0, 100000000};
    nanosleep(&pause, NULL);
  } while (d2k_runtime_mono_ms() - start < 10000);
  close(local.health_runtime_dirfd);
  return ok ? D2KU_OK : D2KU_HEALTH;
}
d2ku_rc d2ku_legacy_health(d2ku_ctx *c, const d2ku_journal *j, d2ku_status *s) {
  if (!c || !j || !s || !c->service_config || !c->clock.monotonic ||
      j->old_kind != D2KU_SOURCE_LEGACY_LOCAL || j->phase != D2KU_VALIDATING ||
      strcmp(j->old_release_id, j->new_release_id))
    return D2KU_INVALID;
  uint64_t ns;
  if (c->clock.monotonic(c->clock.arg, &ns) != D2KU_OK)
    return D2KU_TIME;
  uint64_t now = ns / 1000000;
  d2ku_service_config *sc = c->service_config;
  const char *names[] = {"d2kd.pid", "d2k.pid", "d2k-panel.pid", "d2ktg.pid"};
  int reset = !s->health_observing ||
              strcmp(s->health_transaction, j->transaction_id) ||
              strcmp(s->health_boot, j->progress_boot_id) ||
              strcmp(s->health_release, j->old_release_id) ||
              now < s->health_last_ms ||
              now - s->health_last_ms > D2KU_HEARTBEAT_MS;
  for (unsigned i = 0; i < 4; i++)
    if (j->active_services & (UINT64_C(1) << i)) {
      pid_t pid;
      if (d2ku_legacy_pid(sc, names[i], &pid) != 1 ||
          !d2ku_legacy_process(sc, j->old_release_id, i, pid, 0))
        goto bad;
      char state;
      pid_t parent;
      uint64_t ticks = d2ku_legacy_ticks(pid, &state, &parent);
      if (!reset &&
          (s->health_pid[i] != pid || s->health_start_ticks[i] != ticks))
        goto bad;
      s->health_pid[i] = pid;
      s->health_start_ticks[i] = ticks;
    }
  if (reset) {
    s->health_since_ms = now;
    s->legacy_live_seen_ms = now;
    s->legacy_dp_seen_ms = now;
    s->legacy_live_token = 0;
    s->legacy_dp_elapsed = 0;
  }
  if (j->active_services & 3) {
    uint64_t token, elapsed;
    if (!queue_owner(s->health_pid[0], c->health_queue) || !live(c, &token))
      goto bad;
    if (token != s->legacy_live_token) {
      s->legacy_live_seen_ms = now;
      s->legacy_live_token = token;
    }
    if (stats(c, s->health_pid[0], &elapsed) &&
        elapsed > s->legacy_dp_elapsed) {
      s->legacy_dp_elapsed = elapsed;
      s->legacy_dp_seen_ms = now;
    }
    if (now - s->legacy_live_seen_ms > D2KU_HEARTBEAT_MS ||
        now - s->legacy_dp_seen_ms > D2KU_HEARTBEAT_MS)
      goto bad;
  }
  if ((j->active_services & 4) &&
      (!listener(s->health_pid[2], c->health_panel_port) || !c->health_http ||
       c->health_http(c->health_arg) != D2KU_OK))
    goto bad;
  if ((j->active_services & 8) &&
      (!listener(s->health_pid[3], sc->tg_port) || !telegram_state(sc)))
    goto bad;
  if ((j->active_services & 10) &&
      (!c->health_state || c->health_state(c->health_arg) != D2KU_OK))
    goto bad;
  if ((j->active_services & 9) &&
      (!c->health_rules || c->health_rules(c->health_arg) != D2KU_OK))
    goto bad;
  strcpy(s->health_transaction, j->transaction_id);
  strcpy(s->health_boot, j->progress_boot_id);
  strcpy(s->health_release, j->old_release_id);
  s->health_last_ms = now;
  s->health_observing = 1;
  s->installation_healthy = 0;
  s->external_available = 0;
  s->health_complete = now - s->health_since_ms >= D2KU_VALIDATION_MS;
  return D2KU_OK;
bad:
  s->health_observing = s->health_complete = s->installation_healthy = 0;
  return D2KU_HEALTH;
}
