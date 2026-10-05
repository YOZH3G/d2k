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
  char control[1200], catalog[1200], live[1200], config[1200];
  snprintf(control, sizeof control, "%s/run/d2kd.sock", s->root);
  snprintf(catalog, sizeof catalog, "%s/state/catalog.json", s->root);
  snprintf(live, sizeof live, "%s/live.json", s->runtime);
  snprintf(config, sizeof config, "%s/config", s->root);
  int seen_control = 0, seen_catalog = 0, seen_live = 0, seen_config = 0,
      seen_log = 0;
  for (char *p = data + strlen(data) + 1; p < data + n; p += strlen(p) + 1) {
    const char *want = NULL;
    if (!strcmp(p, "--control")) {
      want = control;
      seen_control = 1;
    }
    if (!strcmp(p, "--catalog")) {
      want = catalog;
      seen_catalog = 1;
    }
    if (!strcmp(p, "--live")) {
      want = live;
      seen_live = 1;
    }
    if (!strcmp(p, "--config")) {
      want = config;
      seen_config = 1;
    }
    if (!strcmp(p, "--plan") || !strcmp(p, "--duration") ||
        !strcmp(p, "--health-file"))
      return 0;
    if (want) {
      p += strlen(p) + 1;
      if (p >= data + n || strcmp(p, want))
        return 0;
    } else if (!strcmp(p, "--queue")) {
      p += strlen(p) + 1;
      if (p >= data + n)
        return 0;
      char *end;
      unsigned long q = strtoul(p, &end, 10);
      if (*end || q != s->ctx->health_queue)
        return 0;
    } else if (!strcmp(p, "--log")) {
      seen_log = 1;
      p += strlen(p) + 1;
      if (p >= data + n)
        return 0;
      char expected[1200];
      snprintf(expected, sizeof expected, "%s/log/%s.log", s->root,
               role == 0   ? "d2kd"
               : role == 1 ? "d2kc"
               : role == 2 ? "d2kpanel"
                           : "d2ktg");
      if (strcmp(p, expected))
        return 0;
    } else if (!strcmp(p, "--https-cache")) {
      p += strlen(p) + 1;
      if (p >= data + n)
        return 0;
      char expected[1200];
      snprintf(expected, sizeof expected, "%s/state/https-cache.json", s->root);
      if (strcmp(p, expected))
        return 0;
    }
  }
  if (role < 2 && (!seen_control || !seen_log))
    return 0;
  if (role == 1 && (!seen_catalog || !seen_live))
    return 0;
  if (role == 3 && !seen_config)
    return 0;
  return 1;
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
