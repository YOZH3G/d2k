#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "legacy_runtime.h"
#include "transaction_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static d2ku_rc probe(d2ku_ctx *c, int saved, const char *bin, const char *arg,
                     int expected, const char *text) {
  int out[2], gate[2];
  if (pipe(out))
    return D2KU_IO;
  if (pipe(gate)) {
    close(out[0]);
    close(out[1]);
    return D2KU_IO;
  }
  pid_t p = fork();
  if (p < 0) {
    close(out[0]);
    close(out[1]);
    close(gate[0]);
    close(gate[1]);
    return D2KU_IO;
  }
  if (!p) {
    close(out[0]);
    close(gate[1]);
    char ch;
    if (read(gate[0], &ch, 1) != 1 || ch != 'G')
      _exit(126);
    close(gate[0]);
    if (setpgid(0, 0) || dup2(out[1], 1) < 0 || dup2(out[1], 2) < 0 ||
        fchdir(saved))
      _exit(126);
    close(out[1]);
    close(3);
    close(4);
    close(5);
    if (arg)
      execl(bin, bin, arg, (char *)NULL);
    else
      execl(bin, bin, (char *)NULL);
    _exit(127);
  }
  close(out[1]);
  close(gate[0]);
  d2ku_rc rc = d2ku_boot_group(c, p, 1);
  if (rc == D2KU_OK && write(gate[1], "G", 1) != 1)
    rc = D2KU_IO;
  close(gate[1]);
  char b[16384] = {0};
  size_t used = 0;
  int status = 0, exited = 0;
  fcntl(out[0], F_SETFL, O_NONBLOCK);
  for (unsigned tick = 0; rc == D2KU_OK && tick < 500; tick++) {
    ssize_t n = read(out[0], b + used, sizeof b - 1 - used);
    if (n > 0)
      used += (size_t)n;
    if (used == sizeof b - 1) {
      rc = D2KU_INCOMPATIBLE;
      break;
    }
    if (waitpid(p, &status, WNOHANG) == p) {
      exited = 1;
      while (used < sizeof b - 1 &&
             (n = read(out[0], b + used, sizeof b - 1 - used)) > 0)
        used += (size_t)n;
      break;
    }
    struct timespec delay = {0, 10000000};
    nanosleep(&delay, NULL);
  }
  close(out[0]);
  if (!exited) {
    kill(-p, SIGKILL);
    kill(p, SIGKILL);
    while (waitpid(p, &status, 0) < 0 && errno == EINTR) {
    }
  }
  d2ku_rc cleanup = d2ku_group_cleanup(p);
  if (cleanup == D2KU_OK)
    cleanup = d2ku_boot_group(c, p, 0);
  if (rc != D2KU_OK)
    return rc;
  if (cleanup != D2KU_OK)
    return cleanup;
  return exited && WIFEXITED(status) && WEXITSTATUS(status) == expected &&
                 strstr(b, text)
             ? D2KU_OK
             : D2KU_INCOMPATIBLE;
}
static uint64_t word(const unsigned char *p, unsigned n, int little) {
  uint64_t v = 0;
  for (unsigned i = 0; i < n; i++)
    v = (v << 8) | p[little ? n - 1 - i : i];
  return v;
}
/* This historical distribution is static ELF. An interpreter/shared object
 * outside the sealed inventory would make the local provenance incomplete. */
static int static_elf(int f, const unsigned char b[64], off_t size) {
  if (memcmp(b, "\177ELF", 4) || (b[4] != 1 && b[4] != 2) ||
      (b[5] != 1 && b[5] != 2) || b[6] != 1)
    return 0;
  int le = b[5] == 1;
  unsigned wide = b[4] == 2;
  if (word(b + 16, 2, le) != 2)
    return 0;
  uint64_t off = word(b + (wide ? 32 : 28), wide ? 8 : 4, le);
  unsigned ents = (unsigned)word(b + (wide ? 54 : 42), 2, le),
           num = (unsigned)word(b + (wide ? 56 : 44), 2, le);
  if (ents != (wide ? 56 : 32) || !num || num > 128 || off > (uint64_t)size ||
      num * ents > (uint64_t)size - off)
    return 0;
  for (unsigned i = 0; i < num; i++) {
    unsigned char p[4];
    if (pread(f, p, 4, (off_t)(off + i * ents)) != 4)
      return 0;
    uint64_t type = word(p, 4, le);
    if (type == 2 || type == 3)
      return 0;
  }
  return 1;
}
static const char *elf_abi(int saved, const char *name) {
  int f = openat(saved, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (f < 0)
    return NULL;
  struct stat s;
  unsigned char b[64];
  ssize_t n = read(f, b, sizeof b);
  int good = !fstat(f, &s) && S_ISREG(s.st_mode) && s.st_uid == geteuid() &&
             !(s.st_mode & 022) && s.st_nlink == 1 && (s.st_mode & 0111);
  good = good && n == 64 && static_elf(f, b, s.st_size);
  close(f);
  if (!good || n != 64 || memcmp(b, "\177ELF", 4) || (b[5] != 1 && b[5] != 2))
    return NULL;
  unsigned machine = b[5] == 1 ? (unsigned)b[18] + 256u * b[19]
                               : (unsigned)b[19] + 256u * b[18];
  if (machine == 183 && b[4] == 2 && b[5] == 1)
    return "arm64";
  if (machine == 40 && b[4] == 1 && b[5] == 1)
    return "arm";
  if (machine == 62 && b[4] == 2 && b[5] == 1)
    return "amd64";
  if (machine == 3 && b[4] == 1 && b[5] == 1)
    return "x86";
  if (machine == 8 && b[4] == 1)
    return b[5] == 1 ? "mipsel" : "mips";
  if (machine == 8 && b[4] == 2 && b[5] == 1)
    return "mips64el";
  if (machine == 21 && b[4] == 2 && b[5] == 2)
    return "ppc64";
  if (machine == 243 && b[4] == 2 && b[5] == 1)
    return "riscv64";
  return NULL;
}
d2ku_rc d2ku_legacy_admit(d2ku_ctx *c, int saved, char abi[9]) {
  const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
  const char *args[] = {"--help", NULL, "--version", "--version"};
  const char *texts[] = {"--queue", "d2kc --control",
                         "features=telegram-control",
                         "features=per-install-enrollment"};
  abi[0] = 0;
  for (unsigned i = 0; i < 4; i++) {
    const char *a = elf_abi(saved, bins[i]);
    if (!a || (i && strcmp(abi, a)))
      return D2KU_INCOMPATIBLE;
    strcpy(abi, a);
    d2ku_rc rc = probe(c, saved, bins[i], args[i], i == 1 ? 2 : 0, texts[i]);
    if (rc != D2KU_OK)
      return rc;
  }
  return d2ku_legacy_protocol(c, saved);
}

/* The known flat S99 profile is recoverable only when effective arguments
 * match its config and retained resources. Defaults below are from the wire12
 * executables, not from a newer CLI. Diagnostics --stats is deliberately reset
 * to one second on recovery; it does not change traffic or personal resources.
 */
static int number(const char *p, unsigned long *v) {
  if (!p || !*p || *p == '-' || *p == '+' || *p == ' ')
    return 0;
  char *end;
  errno = 0;
  *v = strtoul(p, &end, 0);
  return !errno && !*end && *v <= UINT32_MAX;
}
int d2ku_legacy_argv(d2ku_service_config *s, unsigned role, size_t argc,
                     const char *const *argv) {
  if (role > 3 || !argc || argc > 64)
    return 0;
  char control[1200], catalog[1200], live[1200], config[1200], log[1200],
      assets[1200], cache[1200], service[1200], dp[1200], core[1200], tg[1200],
      status[1200], queue[24];
  snprintf(control, sizeof control, "%s/run/d2kd.sock", s->root);
  snprintf(catalog, sizeof catalog, "%s/state/catalog.json", s->root);
  snprintf(live, sizeof live, "%s/live.json", s->runtime);
  snprintf(config, sizeof config, "%s/config", s->root);
  snprintf(log, sizeof log, "%s/log/%s.log", s->root,
           role == 0   ? "d2kd"
           : role == 1 ? "d2kc"
           : role == 2 ? "panel"
                       : "telegram");
  snprintf(assets, sizeof assets, "%s/panel", s->root);
  snprintf(cache, sizeof cache, "%s/state/https-cache.txt", s->root);
  const char *slash = strrchr(s->root, '/');
  if (!slash)
    return 0;
  snprintf(service, sizeof service, "%.*s/etc/init.d/S99d2k",
           (int)(slash - s->root), s->root);
  snprintf(dp, sizeof dp, "%s/run/d2kd.pid", s->root);
  snprintf(core, sizeof core, "%s/run/d2k.pid", s->root);
  snprintf(tg, sizeof tg, "%s/run/d2ktg.pid", s->root);
  /* Historical panel CLI does not consume TG_STATUS from config. */
  snprintf(status, sizeof status, "%s/state/telegram.status", s->root);
  snprintf(queue, sizeof queue, "%u", s->ctx->health_queue);
  /* roles bitmask; kind: text=0, uint32=1, flag=2, diagnostic uint32=3.
   * NULL default means the historical daemon needs the explicit argument. */
  struct option {
    const char *key, *want, *def;
    unsigned roles, kind;
    int seen;
  } opts[] = {
      {"--control", control, NULL, 3, 0, 0},
      {"--catalog", catalog, "/opt/d2k/catalog.json", 2, 0, 0},
      {"--live", live, NULL, 6, 0, 0},
      {"--config", config, "/opt/d2k/config", 12, 0, 0},
      {"--log", log, NULL, 15, 0, 0},
      {"--https-cache", cache, cache, 2, 0, 0},
      {"--assets", assets, "/opt/d2k/panel", 4, 0, 0},
      {"--state-dir", s->state,
       s->legacy_state_configured ? s->state : "/opt/d2k/state", 4, 0, 0},
      {"--listen", s->legacy_listen, s->legacy_listen, 4, 0, 0},
      {"--service", service, "/opt/etc/init.d/S99d2k", 4, 0, 0},
      {"--engine-pid", dp, "/opt/d2k/run/d2kd.pid", 4, 0, 0},
      {"--controller-pid", core, "/opt/d2k/run/d2k.pid", 4, 0, 0},
      {"--telegram-pid", tg, "/opt/d2k/run/d2ktg.pid", 4, 0, 0},
      {"--telegram-status", status, "/opt/d2k/state/telegram.status", 4, 0, 0},
      {"--queue", queue, role == 2 ? queue : "0", 5, 1, 0},
      {"--mode",
       role == 2                          ? s->legacy_mode
       : !strcmp(s->legacy_mode, "apply") ? "apply"
                                          : "observe",
       role == 2 && s->legacy_mode_configured ? s->legacy_mode : "observe", 5,
       0, 0},
      {"--mark", role == 0 ? s->legacy_mark : s->legacy_probe_mark,
       role == 0 ? "0" : "0x2d", 3, 1, 0},
      {"--probe-mark", s->legacy_probe_mark, "0", 1, 1, 0},
      {"--measure-mark", s->legacy_measure_mark, s->legacy_probe_mark, 2, 1, 0},
      {"--flows", s->legacy_flows, "2048", 1, 1, 0},
      {"--udp-reverse-hook", "1", "0", 1, 2, 0},
      {"--queue-len", "1024", "1024", 1, 1, 0},
      {"--copy-range", "1600", "1600", 1, 1, 0},
      {"--sched-slots", "128", "128", 1, 1, 0},
      {"--journal", "256", "256", 1, 1, 0},
      {"--idle", "120", "120", 1, 1, 0},
      {"--duration", "0", "0", 1, 1, 0},
      {"--stats", "1", "10", 1, 3, 0}};
  size_t first = 1;
  if (role == 2) {
    if (argc < 2 || strcmp(argv[1], "serve"))
      return 0;
    first = 2;
  }
  for (size_t i = first; i < argc; i++) {
    size_t k;
    for (k = 0; k < sizeof opts / sizeof *opts; k++)
      if (!strcmp(argv[i], opts[k].key))
        break;
    if (k == sizeof opts / sizeof *opts || !(opts[k].roles & (1u << role)) ||
        opts[k].seen)
      return 0;
    opts[k].seen = 1;
    const char *value = "1";
    if (opts[k].kind != 2) {
      if (++i == argc || !*argv[i])
        return 0;
      value = argv[i];
    }
    opts[k].def = value;
  }
  for (size_t k = 0; k < sizeof opts / sizeof *opts; k++) {
    struct option *o = &opts[k];
    if (!(o->roles & (1u << role)))
      continue;
    /* Panel's implicit live path follows STATE_DIR, not the volatile dir. */
    if (!o->def && role == 2 && !strcmp(o->key, "--live")) {
      char implicit[1200];
      snprintf(implicit, sizeof implicit, "%s/live.json", s->state);
      if (strcmp(implicit, o->want))
        return 0;
      continue;
    }
    if (!o->def)
      return 0;
    if (o->kind) {
      unsigned long a, b;
      if (!number(o->def, &a) || !number(o->want, &b) ||
          (o->kind != 3 && a != b))
        return 0;
    } else if (strcmp(o->def, o->want))
      return 0;
  }
  return 1;
}
static int process_paths(d2ku_service_config *s, pid_t pid, unsigned role) {
  char path[80], data[8192];
  snprintf(path, sizeof path, "/proc/%ld/cmdline", (long)pid);
  int f = open(path, O_RDONLY | O_CLOEXEC);
  if (f < 0)
    return 0;
  ssize_t n = read(f, data, sizeof data);
  close(f);
  if (n <= 0 || n == (ssize_t)sizeof data || data[n - 1])
    return 0;
  const char *argv[64];
  size_t argc = 0;
  for (char *p = data; p < data + n; p += strlen(p) + 1) {
    if (argc == 64)
      return 0;
    argv[argc++] = p;
  }
  return d2ku_legacy_argv(s, role, argc, argv);
}
/* Bind every live pidfile even if an enabled-intent file already exists. The
 * source inode must still be the flat executable, and its held bytes must equal
 * the saved inventory; a copied-but-not-running version is not recoverable. */
d2ku_rc d2ku_legacy_bind(d2ku_ctx *c, int saved) {
  if (!c->service_config)
    return D2KU_INVALID;
  const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
  const char *names[] = {"d2kd.pid", "d2k.pid", "d2k-panel.pid", "d2ktg.pid"};
  int sb = openat(c->bootstrap_prefix_fd, "sbin",
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (sb < 0)
    return D2KU_INVALID;
  d2ku_rc rc = D2KU_OK;
  for (unsigned i = 0; i < 4 && rc == D2KU_OK; i++) {
    pid_t pid;
    int n = d2ku_legacy_pid(c->service_config, names[i], &pid);
    if (n < 0) {
      rc = D2KU_INVALID;
      break;
    }
    if (!n)
      continue;
    char state;
    pid_t parent;
    if (!d2ku_legacy_ticks(pid, &state, &parent) || state == 'Z')
      continue;
    char proc[64];
    snprintf(proc, sizeof proc, "/proc/%ld/exe", (long)pid);
    int a = openat(sb, bins[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC),
        b = openat(saved, bins[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC),
        actual = open(proc, O_RDONLY | O_CLOEXEC);
    struct stat x, y, z;
    int ok = a >= 0 && b >= 0 && actual >= 0 && !fstat(a, &x) &&
             !fstat(b, &y) && !fstat(actual, &z) && x.st_dev == z.st_dev &&
             x.st_ino == z.st_ino && x.st_size == y.st_size;
    unsigned char aa[16384], bb[16384];
    ssize_t k = 0;
    while (ok && (k = read(a, aa, sizeof aa)) > 0)
      if (read(b, bb, (size_t)k) != k || memcmp(aa, bb, (size_t)k))
        ok = 0;
    if (k < 0)
      ok = 0;
    if (a >= 0)
      close(a);
    if (b >= 0)
      close(b);
    if (actual >= 0)
      close(actual);
    if (!ok || !process_paths(c->service_config, pid, i))
      rc = D2KU_HEALTH;
  }
  close(sb);
  return rc;
}
