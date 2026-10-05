#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "legacy.h"
#include "transaction_internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

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
/* Both stable boot and external service/NDM recovery require the same clock
 * and private runtime directory. Caller owns the returned CLOEXEC directory. */
d2ku_rc d2ku_service_recovery_context(d2ku_ctx *c, const char *runtime) {
  if (!c || !runtime || !*runtime || c->health_runtime_dirfd >= 0)
    return D2KU_INVALID;
  if (mkdir(runtime, 0700) && errno != EEXIST)
    return D2KU_IO;
  int fd = open(runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (fd < 0)
    return D2KU_IO;
  if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 077)) {
    close(fd);
    return D2KU_INVALID;
  }
  c->health_runtime_dirfd = fd;
  c->clock.monotonic = mono;
  c->clock.snapshot = sample;
  return D2KU_OK;
}
static int regular(int fd) {
  struct stat s;
  return fd >= 0 && !fstat(fd, &s) && S_ISREG(s.st_mode) &&
         s.st_uid == geteuid() && s.st_nlink == 1 && !(s.st_mode & 022);
}
d2ku_rc d2ku_service_lock_valid(d2ku_ctx *c, int fd) {
  int d = openat(c->root_dirfd, "update-state",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (d < 0)
    return D2KU_INVALID;
  int other = openat(d, "maintenance.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  close(d);
  struct stat a, b;
  int good = regular(fd) && regular(other) && !fstat(fd, &a) &&
             !fstat(other, &b) && a.st_ino == b.st_ino && a.st_dev == b.st_dev;
  if (good) { /* A separately opened description must NOT be able to lock. */
    if (!flock(other, LOCK_EX | LOCK_NB))
      good = 0;
    else if (errno != EAGAIN && errno != EWOULDBLOCK)
      good = 0;
  }
#ifdef __linux__
  if (good) {
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", fd);
    FILE *f = fopen(path, "r");
    good = 0;
    if (f) {
      while (fgets(line, sizeof line, f))
        if (strstr(line, "lock:") && strstr(line, "FLOCK") &&
            strstr(line, "WRITE"))
          good = 1;
      fclose(f);
    }
  }
#endif
  if (other >= 0)
    close(other);
  return good ? D2KU_OK : D2KU_INVALID;
}
static int assign(char *dst, size_t cap, const char *s) {
  size_t n = strlen(s);
  if (n >= cap)
    return 0;
  memcpy(dst, s, n + 1);
  return 1;
}
static int path_ok(const char *p) {
  if (*p != '/')
    return 0;
  for (const char *q = p; *q; q++)
    if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
          (*q >= '0' && *q <= '9') || strchr("/_-.", *q)))
      return 0;
  return !strstr(p, "//") && !strstr(p, "/../") && !strstr(p, "/./") &&
         strcmp(p + strlen(p) - 1, "/") &&
         (strlen(p) < 3 || strcmp(p + strlen(p) - 3, "/.."));
}
static int personal_existing_safe(int root, const char *path) {
  char copy[1024];
  if (!assign(copy, sizeof copy, path))
    return 0;
  int at = dup(root);
  if (at < 0)
    return 0;
  char *save = NULL, *part = strtok_r(copy, "/", &save);
  while (part) {
    char *next = strtok_r(NULL, "/", &save);
    struct stat st;
    if (fstatat(at, part, &st, AT_SYMLINK_NOFOLLOW)) {
      int missing = errno == ENOENT;
      close(at);
      return missing;
    }
    if (st.st_uid != geteuid() || S_ISLNK(st.st_mode) ||
        (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) ||
        (S_ISREG(st.st_mode) && st.st_nlink != 1) ||
        (next && !S_ISDIR(st.st_mode))) {
      close(at);
      return 0;
    }
    if (!next) {
      close(at);
      return 1;
    }
    int fd = openat(at, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(at);
    if (fd < 0)
      return 0;
    at = fd;
    part = next;
  }
  close(at);
  return 1;
}
static d2ku_rc personal(d2ku_ctx *c, const char *root, const char *path,
                        int config) {
  size_t n = strlen(root);
  if (!path_ok(path) || strncmp(path, root, n) || path[n] != '/')
    return D2KU_INCOMPATIBLE;
  const char *p = path + n + 1;
  if (!personal_existing_safe(c->root_dirfd, p))
    return D2KU_INCOMPATIBLE;
  size_t len = strcspn(p, "/");
  if (!len || len > D2KU_ID_MAX)
    return D2KU_INCOMPATIBLE;
  char name[D2KU_ID_MAX + 1];
  memcpy(name, p, len);
  name[len] = 0;
  static const char *reserved[] = {"update-state", "update", "boot", "releases",
                                   "current",      "run",    "log",  "logs",
                                   "snapshots",    "files",  "panel"};
  for (size_t i = 0; i < sizeof reserved / sizeof *reserved; i++)
    if (!strcmp(name, reserved[i]))
      return D2KU_INCOMPATIBLE;
  for (size_t i = 0; i < c->transaction.path_count; i++)
    if (!strcmp(name, c->transaction.paths[i].name))
      return c->transaction.paths[i].configuration == config
                 ? D2KU_OK
                 : D2KU_INCOMPATIBLE;
  if (c->transaction.path_count == D2KU_SNAPSHOT_PATHS_MAX)
    return D2KU_INVALID;
  d2ku_snapshot_path *v = &c->transaction.paths[c->transaction.path_count++];
  assign(v->name, sizeof v->name, name);
  v->configuration = config;
  return D2KU_OK;
}
d2ku_rc d2ku_service_configure(d2ku_ctx *c, const char *root,
                               d2ku_service_config *s) {
  memset(s, 0, sizeof *s);
  s->ctx = c;
  s->identity_required = 1;
  if (!path_ok(root) || !assign(s->root, sizeof s->root, root))
    return D2KU_INVALID;
  if (snprintf(s->state, sizeof s->state, "%s/state", root) >=
      (int)sizeof s->state)
    return D2KU_INVALID;
  const char *runtime_env = getenv("D2K_RUNTIME_DIR");
  if (!assign(s->runtime, sizeof s->runtime,
              runtime_env && *runtime_env ? runtime_env : "/tmp/d2k"))
    return D2KU_INVALID;
  assign(s->panel_host, sizeof s->panel_host, "127.0.0.1");
  char listen[256] = "127.0.0.1:8090", status[1024] = "", ca[1024] = "",
       mode[16] = "apply", tg[16] = "0";
  unsigned long queue = 2000;
  s->tg_port = 1443;
  s->legacy_log_fd = -1;
  strcpy(s->legacy_mark, "0x2d");
  strcpy(s->legacy_probe_mark, "0x2e");
  strcpy(s->legacy_measure_mark, "0x2f");
  strcpy(s->legacy_flows, "2048");
  int fd = openat(c->root_dirfd, "config",
                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (!regular(fd)) {
    if (fd >= 0)
      close(fd);
    return D2KU_INVALID;
  }
  FILE *f = fdopen(fd, "r");
  if (!f) {
    close(fd);
    return D2KU_IO;
  }
  char line[2048];
  d2ku_rc rc = D2KU_OK;
  while (fgets(line, sizeof line, f)) {
    if (!strchr(line, '\n') && !feof(f)) {
      rc = D2KU_INVALID;
      break;
    }
    char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (!*p || *p == '#' || *p == '\n')
      continue;
    char *eq = strchr(p, '=');
    if (!eq) {
      rc = D2KU_INCOMPATIBLE;
      break;
    }
    *eq++ = 0;
    size_t n = strcspn(eq, "\r\n");
    eq[n] = 0;
    if (n >= 2 && (*eq == '\'' || *eq == '"') && eq[n - 1] == *eq) {
      eq[n - 1] = 0;
      eq++;
    }
    char *dest = NULL;
    size_t cap = 0;
    const char *keys[] = {"STATE_DIR",  "D2K_RUNTIME_DIR", "TG_IDENTITY",
                          "TG_STATUS",  "TG_CA_BUNDLE",    "PANEL_LISTEN",
                          "MODE",       "TG_ENABLED",      "MARK",
                          "PROBE_MARK", "MEASURE_MARK",    "FLOWS"};
    char *fields[] = {s->state,
                      s->runtime,
                      s->identity,
                      status,
                      ca,
                      listen,
                      mode,
                      tg,
                      s->legacy_mark,
                      s->legacy_probe_mark,
                      s->legacy_measure_mark,
                      s->legacy_flows};
    size_t caps[] = {sizeof s->state,
                     sizeof s->runtime,
                     sizeof s->identity,
                     sizeof status,
                     sizeof ca,
                     sizeof listen,
                     sizeof mode,
                     sizeof tg,
                     sizeof s->legacy_mark,
                     sizeof s->legacy_probe_mark,
                     sizeof s->legacy_measure_mark,
                     sizeof s->legacy_flows};
    for (unsigned i = 0; i < 12; i++)
      if (!strcmp(p, keys[i])) {
        dest = fields[i];
        cap = caps[i];
        break;
      }
    if (!strcmp(p, "MODE"))
      s->legacy_mode_configured = 1;
    if (!strcmp(p, "STATE_DIR"))
      s->legacy_state_configured = 1;
    if (!strcmp(p, "TG_RELAY_SECRET"))
      s->identity_required = !*eq;
    if (!strcmp(p, "TG_PORT")) {
      char *end;
      unsigned long v = strtoul(eq, &end, 10);
      if (!*eq || *end || !v || v > 65535)
        rc = D2KU_INVALID;
      else
        s->tg_port = (uint16_t)v;
    }
    if (!strcmp(p, "QUEUE_NUM")) {
      char *end;
      errno = 0;
      queue = strtoul(eq, &end, 10);
      if (errno || !*eq || *end || queue > 65535)
        rc = D2KU_INVALID;
    }
    if (dest && !assign(dest, cap, eq))
      rc = D2KU_INVALID;
    if (rc != D2KU_OK)
      break;
  }
  if (ferror(f))
    rc = D2KU_IO;
  fclose(f);
  if (rc != D2KU_OK)
    return rc;
  if (!s->identity[0] &&
      snprintf(s->identity, sizeof s->identity, "%s/tg.identity", s->state) >=
          (int)sizeof s->identity)
    return D2KU_INVALID;
  if (!status[0] && snprintf(status, sizeof status, "%s/telegram.status",
                             s->state) >= (int)sizeof status)
    return D2KU_INVALID;
  strcpy(s->legacy_mode, mode);
  strcpy(s->legacy_listen, listen);
  char *colon = strrchr(listen, ':');
  if (!colon)
    return D2KU_INVALID;
  *colon++ = 0;
  char *end;
  unsigned long port = strtoul(colon, &end, 10);
  if (!*colon || *end || !port || port > 65535)
    return D2KU_INVALID;
  char *host = listen;
  if (*host == '[') {
    host++;
    size_t n = strlen(host);
    if (!n || host[n - 1] != ']')
      return D2KU_INVALID;
    host[n - 1] = 0;
  }
  unsigned char address[16];
  if (inet_pton(AF_INET, host, address) != 1 &&
      inet_pton(AF_INET6, host, address) != 1)
    return D2KU_INVALID;
  if (!assign(s->panel_host, sizeof s->panel_host, host) ||
      !path_ok(s->runtime))
    return D2KU_INVALID;
  if (strcmp(mode, "off") && strcmp(mode, "apply") && strcmp(mode, "observe"))
    return D2KU_INVALID;
  if (strcmp(tg, "0") && strcmp(tg, "1"))
    return D2KU_INVALID;
  s->enabled = (!strcmp(mode, "off") ? 0 : 3) | 4 | (!strcmp(tg, "1") ? 8 : 0);
  c->transaction.path_count = 0;
  char config[1100], catalog[1100];
  snprintf(config, sizeof config, "%s/config", root);
  snprintf(catalog, sizeof catalog, "%s/state/catalog.json", root);
  const char *paths[] = {config, catalog, s->state, s->identity, status};
  for (size_t i = 0; i < 5; i++) {
    rc = personal(c, root, paths[i], i == 0);
    if (rc != D2KU_OK)
      return rc;
  }
  const char *writer_paths[] = {"D2K_INSTAGRAM_MANIFEST",
                                "D2K_INSTAGRAM_SCHED_STATE",
                                "D2K_INSTAGRAM_SCHED_OFFSET"};
  for (unsigned i = 0; i < 3; i++) {
    const char *path = getenv(writer_paths[i]);
    if (path && *path) {
      rc = personal(c, root, path, 0);
      if (rc != D2KU_OK)
        return rc;
    }
  }
  /* A custom in-root trust file is personal configuration. Release-owned
   * files/tg-roots.pem and external system CA files are read-only resources. */
  if (ca[0] && !strncmp(ca, root, strlen(root)) &&
      strncmp(ca + strlen(root), "/files/", 7)) {
    rc = personal(c, root, ca, 1);
    if (rc != D2KU_OK)
      return rc;
  }
  c->health_state_count = 0;
  assign(c->health_state_paths[c->health_state_count++], D2KU_PATH_MAX + 1,
         "state/catalog.json");
  size_t off = strlen(root) + 1;
  if (strlen(s->identity + off) > D2KU_PATH_MAX)
    return D2KU_INVALID;
  assign(c->health_state_paths[c->health_state_count++], D2KU_PATH_MAX + 1,
         s->identity + off);
  if (strlen(status + off) > D2KU_PATH_MAX)
    return D2KU_INVALID;
  assign(c->health_state_paths[c->health_state_count++], D2KU_PATH_MAX + 1,
         status + off);
  c->health_panel_port = (uint16_t)port;
  c->health_queue = (uint16_t)queue;
  c->wire_version = 13;
  c->state_version = 1;
  c->updater_version = 1;
  c->transaction.arg = s;
  c->service_config = s;
  c->transaction.capture = d2ku_service_capture;
  c->transaction.services = d2ku_service_call;
  c->health_arg = s;
  c->health_state = d2ku_service_health_state;
  c->health_http = d2ku_service_health_http;
  c->health_rules = d2ku_service_health_rules;
  return D2KU_OK;
}
static d2ku_rc wait_child(pid_t p) {
  int status;
  while (waitpid(p, &status, 0) < 0) {
    if (errno != EINTR)
      return D2KU_IO;
  }
  return WIFEXITED(status) && !WEXITSTATUS(status) ? D2KU_OK : D2KU_HEALTH;
}
d2ku_rc d2ku_service_capture(void *arg, uint64_t *mask) {
  d2ku_service_config *s = arg;
  if (d2ku_service_lock_valid(s->ctx, s->ctx->maintenance_lock_fd) != D2KU_OK)
    return D2KU_INVALID;
  /* Explicit service intent, saved by the serialized lifecycle. First flat
   * capture uses process pidfiles, so administratively stopped services stay
   * stopped even when MODE is apply. No PID is used as health evidence. */
  int fd = openat(s->ctx->root_dirfd, "update-state/enabled",
                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd >= 0) {
    char b[32] = {0};
    ssize_t n = regular(fd) ? read(fd, b, sizeof b - 1) : -1;
    close(fd);
    char *end;
    unsigned long v = strtoul(b, &end, 10);
    if (n <= 0 || strcmp(end, "\n") || v > 15 || (v & 3) == 1 || (v & 3) == 2)
      return D2KU_INVALID;
    *mask = v;
    s->enabled = v;
    return D2KU_OK;
  }
  if (errno != ENOENT)
    return D2KU_IO;
  *mask = 0;
  const char *names[] = {"d2kd.pid", "d2k.pid", "d2k-panel.pid", "d2ktg.pid"};
  for (unsigned i = 0; i < 4; i++) {
    char path[80], b[32] = {0};
    snprintf(path, sizeof path, "run/%s", names[i]);
    fd = openat(s->ctx->root_dirfd, path,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
      if (errno == ENOENT)
        continue;
      return D2KU_IO;
    }
    ssize_t n = regular(fd) ? read(fd, b, sizeof b - 1) : -1;
    close(fd);
    char *end;
    long pid = strtol(b, &end, 10);
    if (n <= 0 || pid <= 1 || (*end && strcmp(end, "\n")))
      return D2KU_INVALID;
    if (!kill((pid_t)pid, 0)) {
#ifdef __linux__
      const char *binaries[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
      char proc[64], expected[1200], current[D2KU_ID_MAX + 1];
      struct stat actual, want;
      snprintf(proc, sizeof proc, "/proc/%ld/exe", pid);
      if (d2ku_tx_current(s->ctx, current) == D2KU_OK)
        snprintf(expected, sizeof expected, "%s/releases/%s/%s", s->root,
                 current, binaries[i]);
      else {
        char prefix[1024];
        assign(prefix, sizeof prefix, s->root);
        char *slash = strrchr(prefix, '/');
        if (!slash)
          return D2KU_INVALID;
        *slash = 0;
        snprintf(expected, sizeof expected, "%s/sbin/%s", prefix, binaries[i]);
      }
      if (stat(proc, &actual) || stat(expected, &want) ||
          actual.st_ino != want.st_ino || actual.st_dev != want.st_dev)
        return D2KU_HEALTH;
#endif
      *mask |= UINT64_C(1) << i;
    } else if (errno != ESRCH)
      return D2KU_IO;
  }
  if ((*mask & 3) == 1 || (*mask & 3) == 2)
    return D2KU_HEALTH;
  s->enabled = *mask;
  return D2KU_OK;
}
d2ku_rc d2ku_service_call(void *arg, const char *action, const char *id,
                          uint64_t mask) {
  d2ku_service_config *s = arg;
  d2ku_ctx *c = s->ctx;
  if (d2ku_service_lock_valid(c, c->maintenance_lock_fd) != D2KU_OK)
    return D2KU_INVALID;
  char program[1200], bits[24];
  snprintf(program, sizeof program, "%s/boot/d2k-service-adapter", s->root);
  snprintf(bits, sizeof bits, "%llu", (unsigned long long)mask);
  int boot = openat(c->root_dirfd, "boot",
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  int binary = boot < 0 ? -1
                        : openat(boot, "d2k-service-adapter",
                                 O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  int trusted = regular(binary);
  if (binary >= 0)
    close(binary);
  if (boot >= 0)
    close(boot);
  if (!trusted)
    return D2KU_INVALID;
  /* Hold the child in our group until the stable supervisor acknowledges its
   * separate transient group. Daemons launched by init detach and close FD4. */
  int gate[2];
  if (pipe(gate))
    return D2KU_IO;
  pid_t owner = getpid(), p = fork();
  if (p < 0) {
    close(gate[0]);
    close(gate[1]);
    return D2KU_IO;
  }
  if (!p) {
    close(gate[1]);
#ifdef __linux__
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != owner)
      _exit(126);
#else
    (void)owner;
#endif
    char go;
    if (read(gate[0], &go, 1) != 1 || go != 'G')
      _exit(126);
    close(gate[0]);
    if (setpgid(0, 0) || dup2(c->maintenance_lock_fd, 4) < 0)
      _exit(126);
    fcntl(4, F_SETFD, 0);
    close(3);
    close(5);
    execl(program, program, "--root", s->root, "--maintenance-fd", "4", action,
          id, bits, (char *)NULL);
    _exit(127);
  }
  close(gate[0]);
  d2ku_rc r = d2ku_boot_group(c, p, 1);
  if (r == D2KU_OK) {
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &set, &old);
    if (write(gate[1], "G", 1) != 1)
      r = D2KU_IO;
    if (r != D2KU_OK && errno == EPIPE) {
      int caught;
      sigwait(&set, &caught);
    }
    sigprocmask(SIG_SETMASK, &old, NULL);
  }
  close(gate[1]);
  int status = 0, exited = 0;
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  while (r == D2KU_OK) {
    pid_t w = waitpid(p, &status, WNOHANG);
    if (w == p) {
      exited = 1;
      break;
    }
    if (w < 0 && errno != EINTR) {
      r = D2KU_IO;
      break;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) ||
        now.tv_sec - start.tv_sec >= 30) {
      r = D2KU_HEALTH;
      break;
    }
    struct timespec delay = {0, 10000000};
    nanosleep(&delay, NULL);
  }
  if (!exited) {
    kill(-p, SIGKILL);
    kill(p, SIGKILL);
    while (waitpid(p, &status, 0) < 0 && errno == EINTR) {
    }
  }
  d2ku_rc cleanup = d2ku_group_cleanup(p);
  if (cleanup == D2KU_OK)
    cleanup = d2ku_boot_group(c, p, 0);
  if (r != D2KU_OK)
    return r;
  if (cleanup != D2KU_OK)
    return cleanup;
  return WIFEXITED(status) && !WEXITSTATUS(status) ? D2KU_OK : D2KU_HEALTH;
}
static int open_beneath(int base, const char *path) {
  char b[1024];
  if (!assign(b, sizeof b, path))
    return -1;
  int d = dup(base);
  if (d < 0)
    return -1;
  char *save = NULL, *p = strtok_r(b, "/", &save);
  while (p) {
    char *next = strtok_r(NULL, "/", &save);
    if (!strcmp(p, ".") || !strcmp(p, "..")) {
      close(d);
      return -1;
    }
    int f = openat(d, p,
                   O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                       (next ? O_DIRECTORY : 0));
    close(d);
    if (f < 0)
      return -1;
    d = f;
    p = next;
  }
  return d;
}
d2ku_rc d2ku_service_health_state(void *arg) {
  d2ku_service_config *s = arg;
  uint64_t bits;
  d2ku_rc rc = d2ku_service_capture(s, &bits);
  if (rc != D2KU_OK)
    return rc;
  for (unsigned i = 0; i < 3; i++) {
    if (i == 1 && !s->identity_required)
      continue;
    if (!(bits & (i ? 8 : 2)))
      continue;
    int f = open_beneath(s->ctx->root_dirfd, s->ctx->health_state_paths[i]);
    int good = regular(f);
    if (f >= 0)
      close(f);
    if (!good)
      return D2KU_HEALTH;
  }
  return D2KU_OK;
}
d2ku_rc d2ku_service_health_rules(void *arg) {
  d2ku_service_config *s = arg;
  uint64_t mask;
  d2ku_rc r = d2ku_service_capture(s, &mask);
  return r == D2KU_OK ? d2ku_service_call(s, "health-rules", "-", mask) : r;
}
d2ku_rc d2ku_service_health_http(void *arg) {
  d2ku_service_config *s = arg;
  char port[8];
  snprintf(port, sizeof port, "%u", s->ctx->health_panel_port);
  struct addrinfo hints = {0}, *addr = NULL;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  const char *host = s->panel_host;
  if (!strcmp(host, "0.0.0.0"))
    host = "127.0.0.1";
  if (!strcmp(host, "::"))
    host = "::1";
  if (getaddrinfo(host, port, &hints, &addr))
    return D2KU_HEALTH;
  int fd = socket(addr->ai_family, SOCK_STREAM, 0);
  if (fd < 0) {
    freeaddrinfo(addr);
    return D2KU_HEALTH;
  }
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fcntl(fd, F_SETFL, O_NONBLOCK);
  int r = connect(fd, addr->ai_addr, addr->ai_addrlen);
  freeaddrinfo(addr);
  struct pollfd p = {fd, POLLOUT, 0};
  int err = 0;
  socklen_t len = sizeof err;
  int good = (!r || errno == EINPROGRESS) && poll(&p, 1, 2000) > 0 &&
             !getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) && !err;
  const char req[] =
      "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
#ifdef SO_NOSIGPIPE
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
  if (good)
    good = send(fd, req, sizeof req - 1, MSG_NOSIGNAL) == sizeof req - 1;
  char b[16] = {0};
  size_t n = 0;
  p.events = POLLIN;
  while (good && n < 12) {
    good = poll(&p, 1, 2000) > 0;
    if (good) {
      ssize_t k = recv(fd, b + n, 12 - n, 0);
      if (k <= 0)
        good = 0;
      else
        n += (size_t)k;
    }
  }
  close(fd);
  return good && (!strncmp(b, "HTTP/1.0 200", 12) ||
                  !strncmp(b, "HTTP/1.1 200", 12))
             ? D2KU_OK
             : D2KU_HEALTH;
}
d2ku_rc d2ku_service_dispatch(d2ku_service_config *s, const char *action,
                              const char *release, uint64_t mask) {
  d2ku_ctx *c = s->ctx;
  if (mask > 15 || (mask & 3) == 1 || (mask & 3) == 2 ||
      d2ku_service_lock_valid(c, c->maintenance_lock_fd) != D2KU_OK)
    return D2KU_INVALID;
  struct stat lifecycle;
  if (!fstatat(c->root_dirfd, "update-state/lifecycle", &lifecycle,
               AT_SYMLINK_NOFOLLOW) &&
      strcmp(action, "uninstall") && strncmp(action, "health-", 7))
    return D2KU_BUSY;
  if (!strcmp(action, "health-state"))
    return d2ku_service_health_state(s);
  if (!strcmp(action, "health-http"))
    return d2ku_service_health_http(s);
  static const char *actions[] = {"legacy-greet",
                                  "start",
                                  "stop",
                                  "remove-rules",
                                  "health-rules",
                                  "restart",
                                  "engine-start",
                                  "engine-stop",
                                  "engine-restart",
                                  "telegram-enable",
                                  "telegram-disable",
                                  "telegram-restart",
                                  "telegram-reapply",
                                  "reapply",
                                  "ppe-ensure",
                                  "status",
                                  "heal",
                                  "uninstall",
                                  "dns-tick",
                                  "dns-refresh",
                                  "dns-remove",
                                  "log-tick",
                                  "tg-tick",
                                  "tg-heal",
                                  "tg-stop-rules",
                                  "ppe-remove"};
  int valid = 0;
  for (size_t i = 0; i < sizeof actions / sizeof *actions; i++)
    if (!strcmp(action, actions[i]))
      valid = 1;
  if (!valid)
    return D2KU_INVALID;
  char id[D2KU_ID_MAX + 1];
  if (!strcmp(release, "-")) {
    if (d2ku_tx_current(c, id) != D2KU_OK)
      return D2KU_INVALID;
    release = id;
  }
  if (strlen(release) > D2KU_ID_MAX || !*release ||
      strspn(release, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123"
                      "456789._-") != strlen(release) ||
      *release == '.')
    return D2KU_INVALID;
  unsigned char legacy_hash[32];
  d2ku_rc legacy = d2ku_legacy_source(c, release, legacy_hash);
  if (legacy != D2KU_OK && legacy != D2KU_ABSENT)
    return legacy;
  if (!strcmp(action, "legacy-greet"))
    return legacy == D2KU_OK ? d2ku_legacy_greet(s, release) : D2KU_INVALID;
  if (legacy == D2KU_OK) {
    d2ku_rc pre = d2ku_legacy_before(s, action, release, mask);
    if (pre != D2KU_OK)
      return pre;
  }
  char dir[1200], script[1300], bits[24];
  snprintf(dir, sizeof dir, "%s/releases/%s", s->root, release);
  snprintf(script, sizeof script, "%s/S99d2k", dir);
  snprintf(bits, sizeof bits, "%llu", (unsigned long long)mask);
  int file = open_beneath(c->root_dirfd, script + strlen(s->root) + 1);
  int good = regular(file);
  if (file >= 0)
    close(file);
  if (!good)
    return D2KU_INVALID;
  pid_t p = fork();
  if (p < 0)
    return D2KU_IO;
  if (!p) {
    if (dup2(c->maintenance_lock_fd, 4) < 0)
      _exit(126);
    fcntl(4, F_SETFD, 0);
    close(3);
    close(5);
    setenv("D2K_DIR", s->root, 1);
    setenv("D2K_RELEASE_ROOT", dir, 1);
    setenv("D2K_MANAGED_INTERNAL", "1", 1);
    if (legacy == D2KU_OK)
      setenv("D2K_LEGACY_LOCAL", "1", 1);
    else
      unsetenv("D2K_LEGACY_LOCAL");
    execl("/bin/sh", "sh", script, "--managed", action, bits, (char *)NULL);
    _exit(127);
  }
  d2ku_rc dispatched = wait_child(p);
  if (legacy == D2KU_OK) {
    d2ku_rc after = d2ku_legacy_after(s, action, release, mask);
    if (dispatched == D2KU_OK)
      dispatched = after;
  }
  return dispatched;
}
