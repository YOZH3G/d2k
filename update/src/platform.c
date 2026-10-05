#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "daemon.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/timex.h>
#else
#include <sys/sysctl.h>
#include <sys/time.h>
#endif
/* libc timezone state and getenv/setenv are process global. Every calendar
 * snapshot and every refresh use this same lock, independently of IPC state. */
static pthread_mutex_t timezone_lock = PTHREAD_MUTEX_INITIALIZER;
static int timezone_initialized, system_timezone;
static int timezone_valid(const char *s) {
  if (!s || !*s || strlen(s) > D2KU_TIMEZONE_MAX)
    return 0;
  for (; *s; s++)
    if ((unsigned char)*s < 33 || (unsigned char)*s > 126)
      return 0;
  return 1;
}
static d2ku_rc timezone_file(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT ? D2KU_OK : D2KU_TIME;
  struct stat st;
  char text[D2KU_TIMEZONE_MAX + 2];
  ssize_t n;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 ||
      st.st_size > D2KU_TIMEZONE_MAX + 1 ||
      (n = read(fd, text, sizeof text - 1)) != st.st_size) {
    close(fd);
    return D2KU_TIME;
  }
  close(fd);
  text[n] = 0;
  while (n && text[n - 1] == '\n')
    text[--n] = 0;
  if (!timezone_valid(text) || setenv("TZ", text, 1))
    return D2KU_TIME;
  tzset();
  return D2KU_OK;
}
d2ku_rc d2ku_platform_timezone(const char *path) {
  if (!path)
    return D2KU_INVALID;
  pthread_mutex_lock(&timezone_lock);
  d2ku_rc r = timezone_file(path);
  pthread_mutex_unlock(&timezone_lock);
  return r;
}
static d2ku_rc calendar(d2ku_clock_sample *s, time_t now) {
  pthread_mutex_lock(&timezone_lock);
  d2ku_rc r = D2KU_OK;
  if (!timezone_initialized) {
    const char *tz = getenv("TZ");
    system_timezone = !tz || !*tz;
    timezone_initialized = 1;
  }
  if (system_timezone)
    r = timezone_file("/etc/TZ");
  const char *tz = getenv("TZ");
  if (tz && *tz && !timezone_valid(tz))
    r = D2KU_TIME;
  struct tm local;
  if (r == D2KU_OK && !localtime_r(&now, &local))
    r = D2KU_TIME;
  if (r == D2KU_OK) {
    s->local_date = (local.tm_year + 1900) * 10000 + (local.tm_mon + 1) * 100 +
                    local.tm_mday;
    s->local_minute = (unsigned)(local.tm_hour * 60 + local.tm_min);
    if (tz && *tz)
      strcpy(s->timezone, tz);
    else if (!strftime(s->timezone, sizeof s->timezone, "%Z", &local))
      r = D2KU_TIME;
  }
  pthread_mutex_unlock(&timezone_lock);
  return r;
}
static d2ku_rc monotonic(void *arg, uint64_t *n) {
  (void)arg;
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return D2KU_TIME;
  *n = (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
  return D2KU_OK;
}
static d2ku_rc snapshot(void *arg, d2ku_clock_sample *s) {
  (void)arg;
  memset(s, 0, sizeof *s);
  uint64_t n;
  if (monotonic(NULL, &n) != D2KU_OK)
    return D2KU_TIME;
  s->mono_ms = n / 1000000;
  time_t now = time(NULL);
  if (now < 0 || calendar(s, now) != D2KU_OK)
    return D2KU_TIME;
  s->utc_seconds = now;
#ifdef __linux__
  int fd = open("/proc/sys/kernel/random/boot_id",
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return D2KU_TIME;
  ssize_t k = read(fd, s->boot_id, sizeof s->boot_id - 1);
  close(fd);
  if (k <= 0)
    return D2KU_TIME;
  s->boot_id[k] = 0;
  s->boot_id[strcspn(s->boot_id, "\n")] = 0;
  struct timex tx = {0};
  int state = adjtimex(&tx);
  s->synchronized = state >= 0 && state != TIME_ERROR &&
                    !(tx.status & (STA_UNSYNC | STA_CLOCKERR));
#else
  struct timeval boot;
  size_t len = sizeof boot;
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};
  if (sysctl(mib, 2, &boot, &len, NULL, 0))
    return D2KU_TIME;
  snprintf(s->boot_id, sizeof s->boot_id, "darwin-%lld-%d",
           (long long)boot.tv_sec, (int)boot.tv_usec);
  /* Darwin local tests have no production synchronization adapter. Unknown
   * is deliberately not treated as synchronized based on plausible wall time.
   */
  s->synchronized = 0;
#endif
  return D2KU_OK;
}
static d2ku_rc wall(void *arg, int64_t *utc) {
  d2ku_clock_sample s;
  d2ku_rc r = d2ku_read_clock(arg, &s);
  if (r == D2KU_OK)
    *utc = s.utc_seconds;
  return r;
}
d2ku_rc d2ku_platform_clock(d2ku_clock *c) {
  if (!c)
    return D2KU_INVALID;
  c->arg = c;
  c->snapshot = snapshot;
  c->wall = wall;
  c->monotonic = monotonic;
  d2ku_clock_sample sample = {0};
  return calendar(&sample, time(NULL));
}
static int copy(char *dst, size_t cap, const char *s) {
  if (!*s || strlen(s) >= cap)
    return 0;
  strcpy(dst, s);
  return 1;
}
static int hex(char c) {
  return c >= '0' && c <= '9'   ? c - '0'
         : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                : -1;
}
d2ku_rc d2ku_daemon_config(d2ku_daemon *d, const char *fixture) {
  int fd = fixture ? open(fixture, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
                   : openat(d->ctx->root_dirfd, "boot/update.conf",
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 022) || st.st_nlink != 1 || st.st_size <= 0 ||
      st.st_size > 16384) {
    close(fd);
    return D2KU_INVALID;
  }
  FILE *f = fdopen(fd, "r");
  if (!f) {
    close(fd);
    return D2KU_IO;
  }
  char line[4096];
  d2ku_ctx *c = d->ctx;
  unsigned seen = 0;
  d2ku_rc r = D2KU_INVALID;
  c->trust_count = c->transport_host_count = 0;
  if (!fgets(line, sizeof line, f) || strcmp(line, "D2KU-CONFIG-1\n"))
    goto done;
  while (fgets(line, sizeof line, f)) {
    size_t n = strlen(line);
    if (!n || line[n - 1] != '\n')
      goto done;
    line[--n] = 0;
    char *eq = strchr(line, '=');
    if (!eq)
      goto done;
    *eq++ = 0;
    unsigned bit = 0;
    if (!strcmp(line, "feed")) {
      bit = 1;
      if (strncmp(eq, "https://", 8) || strchr(eq, '@') || strchr(eq, '?') ||
          strchr(eq, '#') || eq[strlen(eq) - 1] == '/' ||
          !copy(d->feed, sizeof d->feed, eq))
        goto done;
    } else if (!strcmp(line, "ca")) {
      bit = 2;
      if (*eq != '/' || !copy(c->ca_bundle, sizeof c->ca_bundle, eq))
        goto done;
    } else if (!strcmp(line, "abi")) {
      bit = 4;
      const char *abis[] = {"arm64", "arm", "mipsel", "mips",   "mips64el",
                            "amd64", "x86", "ppc64",  "riscv64"};
      int valid = 0;
      for (size_t k = 0; k < 9; k++)
        valid |= !strcmp(eq, abis[k]);
      if (!valid || !copy(c->abi, sizeof c->abi, eq))
        goto done;
    } else if (!strcmp(line, "build")) {
      bit = 8;
      char *end;
      errno = 0;
      long long v = strtoll(eq, &end, 10);
      if (errno || *end || v <= 0)
        goto done;
      c->clock.build_timestamp = v;
    } else if (!strcmp(line, "host")) {
      if (c->transport_host_count >= D2KU_HOSTS_MAX ||
          !copy(c->transport_hosts[c->transport_host_count],
                sizeof c->transport_hosts[0], eq))
        goto done;
      for (const char *p = eq; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || strchr(".-", *p)))
          goto done;
      c->transport_host_count++;
    } else if (!strcmp(line, "key")) {
      char h[65], tail;
      long long before, after;
      if (c->trust_count >= D2KU_KEYS_MAX ||
          sscanf(eq, "%64s %lld %lld %c", h, &before, &after, &tail) != 3 ||
          strlen(h) != 64 || before < 0 || after <= before)
        goto done;
      d2ku_key *key = &c->trust[c->trust_count];
      for (size_t k = 0; k < 32; k++) {
        int a = hex(h[k * 2]), b = hex(h[k * 2 + 1]);
        if (a < 0 || b < 0)
          goto done;
        key->public_key[k] = (unsigned char)(a * 16 + b);
      }
      key->not_before = before;
      key->not_after = after;
      c->trust_count++;
    } else
      goto done;
    if (bit && (seen & bit))
      goto done;
    seen |= bit;
  }
  if (!ferror(f) && seen == 15 && c->trust_count && c->transport_host_count)
    r = D2KU_OK;
done:
  fclose(f);
  return r;
}
d2ku_rc d2ku_daemon_refresh(void *arg) {
  d2ku_daemon *d = arg;
  d2ku_ctx *c = d->ctx;
  d2ku_rc r = d2ku_service_configure(c, d->root, &d->services);
  if (r != D2KU_OK)
    return r;
  if (c->health_runtime_dirfd >= 0)
    close(c->health_runtime_dirfd);
  c->health_runtime_dirfd = -1;
  r = d2ku_service_recovery_context(c, d->services.runtime);
  if (r != D2KU_OK)
    return r;
  r = d2ku_platform_clock(&c->clock);
  d2ku_clock_sample now = {0};
  if (r == D2KU_OK && c->clock.snapshot(c->clock.arg, &now) == D2KU_OK) {
    pthread_mutex_lock(&d->mutex);
    strcpy(d->timezone, now.timezone);
    pthread_mutex_unlock(&d->mutex);
  }
  return r;
}
