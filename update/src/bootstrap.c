#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../../runtime/d2k_runtime.h"
#include "d2k_update.h"
#include "legacy.h"
#include "transaction_internal.h"
#include <dirent.h>
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
/* Local bootstrap only: caller supplies an explicitly verified local bundle.
 * No downloads or acceptance of unsigned remote files. The old inventory is
 * retained permanently; a pending marker always completes from that inventory.
 */
static const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
static const char *helpers[] = {
    "d2k-fw-heal.sh",        "d2k-tg-firewall.sh",
    "d2k-tg-watchdog.sh",    "d2k-ppe-deoffload.sh",
    "d2k-instagram-dns.sh",  "d2k-instagram-dns-scheduler.sh",
    "d2k-log-maintenance.sh"};
static const char *bundle[] = {"d2k-update-boot", "d2k-service-adapter",
                               "S99d2k",          "S98d2k-update",
                               "001-d2k.sh",      "uninstall.sh"};
static d2ku_rc syncfd(d2ku_ctx *c, int fd) {
  return c->sync_fd ? c->sync_fd(c->io_arg, fd)
                    : (fsync(fd) ? D2KU_IO : D2KU_OK);
}
static int dir(d2ku_ctx *c, int at, const char *name, int create) {
  if (create && mkdirat(at, name, 0700) && errno != EEXIST)
    return -1;
  int f = openat(at, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  struct stat s;
  if (f < 0)
    return -1;
  if (fstat(f, &s) || s.st_uid != geteuid() || (s.st_mode & 022) ||
      (create && syncfd(c, at) != D2KU_OK)) {
    close(f);
    return -1;
  }
  return f;
}
static d2ku_rc writeall(int fd, const void *v, size_t n) {
  const char *p = v;
  while (n) {
    ssize_t k = write(fd, p, n);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      return D2KU_IO;
    p += k;
    n -= (size_t)k;
  }
  return D2KU_OK;
}
static int temporary(int dirfd, char name[256]) {
  static unsigned long counter;
  for (unsigned i = 0; i < 1024; i++) {
    snprintf(name, 256, ".bootstrap-%ld-%lu", (long)getpid(), ++counter);
    int fd = openat(dirfd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0 || errno != EEXIST)
      return fd;
  }
  return -1;
}
static d2ku_rc atomic(d2ku_ctx *c, int at, const char *name, const void *data,
                      size_t n, mode_t mode) {
  char temp[256];
  int f = temporary(at, temp);
  if (f < 0)
    return D2KU_IO;
  struct stat s;
  d2ku_rc r = (!fstat(f, &s) && S_ISREG(s.st_mode) && s.st_nlink == 1 &&
               s.st_uid == geteuid())
                  ? writeall(f, data, n)
                  : D2KU_INVALID;
  if (r == D2KU_OK && fchmod(f, mode))
    r = D2KU_IO;
  if (r == D2KU_OK)
    r = syncfd(c, f);
  close(f);
  if (r == D2KU_OK && renameat(at, temp, at, name))
    r = D2KU_IO;
  if (r == D2KU_OK)
    r = syncfd(c, at);
  return r;
}
static d2ku_rc copy_file(d2ku_ctx *c, int from, const char *src, int to,
                         const char *dst) {
  int f = openat(from, src, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
  struct stat s;
  if (f < 0)
    return D2KU_IO;
  if (fstat(f, &s) || !S_ISREG(s.st_mode) || s.st_nlink != 1 ||
      s.st_uid != geteuid() || (s.st_mode & 022) || s.st_size < 0 ||
      s.st_size > 128 * 1024 * 1024) {
    close(f);
    return D2KU_INVALID;
  }
  char temp[256];
  int out = temporary(to, temp);
  if (out < 0) {
    close(f);
    return D2KU_IO;
  }
  d2ku_rc r = D2KU_OK;
  char b[16384];
  ssize_t n;
  while ((n = read(f, b, sizeof b)) != 0) {
    if (n < 0) {
      if (errno == EINTR)
        continue;
      r = D2KU_IO;
      break;
    }
    if ((r = writeall(out, b, (size_t)n)) != D2KU_OK)
      break;
  }
  struct stat after;
  if (r == D2KU_OK && (fstat(f, &after) || after.st_size != s.st_size ||
#ifdef __APPLE__
                       after.st_mtimespec.tv_sec != s.st_mtimespec.tv_sec ||
                       after.st_mtimespec.tv_nsec != s.st_mtimespec.tv_nsec ||
                       after.st_ctimespec.tv_sec != s.st_ctimespec.tv_sec ||
                       after.st_ctimespec.tv_nsec != s.st_ctimespec.tv_nsec
#else
                       after.st_mtim.tv_sec != s.st_mtim.tv_sec ||
                       after.st_mtim.tv_nsec != s.st_mtim.tv_nsec ||
                       after.st_ctim.tv_sec != s.st_ctim.tv_sec ||
                       after.st_ctim.tv_nsec != s.st_ctim.tv_nsec
#endif
                       ))
    r = D2KU_RECOVERY;
  if (r == D2KU_OK && fchmod(out, s.st_mode & 0777))
    r = D2KU_IO;
  if (r == D2KU_OK)
    r = syncfd(c, out);
  close(out);
  close(f);
  if (r == D2KU_OK && renameat(to, temp, to, dst))
    r = D2KU_IO;
  if (r == D2KU_OK)
    r = syncfd(c, to);
  return r;
}
static int positive_digits(const char **p) {
  if (**p < '1' || **p > '9')
    return 0;
  do {
    (*p)++;
  } while (**p >= '0' && **p <= '9');
  return 1;
}
static int temp_name(const char *name) {
  const char *p = name;
  if (!strncmp(p, ".bootstrap-", 11)) {
    p += 11;
    if (!positive_digits(&p) || *p++ != '-' || !positive_digits(&p))
      return 0;
  } else if (!strncmp(p, ".legacy-", 8)) {
    p += 8;
    if (!positive_digits(&p))
      return 0;
  } else
    return 0;
  return !*p;
}
/* Reserve the construction namespace before copying source resources. This
 * makes cleanup incapable of silently deleting a legitimate admitted asset. */
static d2ku_rc source_names(d2ku_ctx *c, int at, unsigned depth) {
  if (depth > 12)
    return D2KU_INVALID;
  int f = dup(at);
  if (f < 0)
    return D2KU_IO;
  DIR *d = fdopendir(f);
  if (!d) {
    close(f);
    return D2KU_IO;
  }
  rewinddir(d);
  struct dirent *e;
  d2ku_rc rc = D2KU_OK;
  unsigned count = 0;
  while (rc == D2KU_OK && (e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    if (++count > 1024 || !strncmp(e->d_name, ".bootstrap-", 11) ||
        !strncmp(e->d_name, ".legacy-", 8) ||
        !strcmp(e->d_name, ".d2ku-legacy")) {
      rc = D2KU_INCOMPATIBLE;
      break;
    }
    struct stat st;
    if (fstatat(at, e->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      rc = D2KU_IO;
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      int sub = dir(c, at, e->d_name, 0);
      rc = sub < 0 ? D2KU_INVALID : source_names(c, sub, depth + 1);
      if (sub >= 0)
        close(sub);
    }
  }
  closedir(d);
  return rc;
}
/* Private construction trees may contain an interrupted copy's temporary
 * inode. Remove only our reserved names, with the same owner/link/type checks;
 * never omit arbitrary published resources from the final seal. */
static d2ku_rc clean_temps(d2ku_ctx *c, int at, unsigned depth) {
  if (depth > 12)
    return D2KU_INVALID;
  int copied = dup(at);
  if (copied < 0)
    return D2KU_IO;
  DIR *d = fdopendir(copied);
  if (!d) {
    close(copied);
    return D2KU_IO;
  }
  rewinddir(d);
  d2ku_rc rc = D2KU_OK;
  struct dirent *e;
  int changed = 0;
  while (rc == D2KU_OK && (e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    struct stat st;
    if (fstatat(at, e->d_name, &st, AT_SYMLINK_NOFOLLOW) ||
        st.st_uid != geteuid() || (st.st_mode & 022)) {
      rc = D2KU_INVALID;
      break;
    }
    if (!strncmp(e->d_name, ".bootstrap-", 11) ||
        !strncmp(e->d_name, ".legacy-", 8)) {
      if (!temp_name(e->d_name) || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        rc = D2KU_INVALID;
        break;
      }
      if (unlinkat(at, e->d_name, 0)) {
        rc = D2KU_IO;
        break;
      }
      changed = 1;
    } else if (S_ISDIR(st.st_mode)) {
      int sub = dir(c, at, e->d_name, 0);
      rc = sub < 0 ? D2KU_INVALID : clean_temps(c, sub, depth + 1);
      if (sub >= 0)
        close(sub);
    }
  }
  closedir(d);
  if (rc == D2KU_OK && changed)
    rc = syncfd(c, at);
  return rc;
}
static int cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}
static d2ku_rc tree(d2ku_ctx *c, int from, int to, EVP_MD_CTX *hash,
                    unsigned depth) {
  if (depth > 12)
    return D2KU_INVALID;
  int d = dup(from);
  if (d < 0)
    return D2KU_IO;
  DIR *list = fdopendir(d);
  if (!list) {
    close(d);
    return D2KU_IO;
  }
  rewinddir(list);
  char *names[1024];
  size_t count = 0;
  struct dirent *e;
  d2ku_rc rc = D2KU_OK;
  while ((e = readdir(list))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    if (!strncmp(e->d_name, ".bootstrap-", 11))
      continue;
    if (count == 1024) {
      rc = D2KU_INVALID;
      break;
    }
    names[count] = strdup(e->d_name);
    if (!names[count]) {
      rc = D2KU_IO;
      break;
    }
    count++;
  }
  closedir(list);
  qsort(names, count, sizeof *names, cmp);
  for (size_t i = 0; i < count && rc == D2KU_OK; i++) {
    struct stat s;
    if (fstatat(from, names[i], &s, AT_SYMLINK_NOFOLLOW) ||
        s.st_uid != geteuid() || (s.st_mode & 022)) {
      rc = D2KU_INVALID;
      break;
    }
    if (hash)
      EVP_DigestUpdate(hash, names[i], strlen(names[i]) + 1);
    if (S_ISDIR(s.st_mode)) {
      if (hash)
        EVP_DigestUpdate(hash, "D", 1);
      int a = dir(c, from, names[i], 0),
          b = to < 0 ? -1 : dir(c, to, names[i], 1);
      if (a < 0 || (to >= 0 && b < 0))
        rc = D2KU_IO;
      else
        rc = tree(c, a, b, hash, depth + 1);
      if (a >= 0)
        close(a);
      if (b >= 0)
        close(b);
      if (hash)
        EVP_DigestUpdate(hash, "E", 1);
    } else if (S_ISREG(s.st_mode) && s.st_nlink == 1) {
      if (to >= 0)
        rc = copy_file(c, from, names[i], to, names[i]);
      if (hash && rc == D2KU_OK) {
        char meta[80];
        int z = snprintf(meta, sizeof meta,
                         "F%u:%llu:", (unsigned)(s.st_mode & 0777),
                         (unsigned long long)s.st_size);
        EVP_DigestUpdate(hash, meta, (size_t)z);
        int f = openat(from, names[i],
                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (f < 0) {
          rc = D2KU_IO;
          break;
        }
        char b[16384];
        ssize_t n;
        while ((n = read(f, b, sizeof b)) > 0)
          EVP_DigestUpdate(hash, b, (size_t)n);
        if (n < 0)
          rc = D2KU_IO;
        close(f);
      }
    } else
      rc = D2KU_INVALID;
  }
  for (size_t i = 0; i < count; i++)
    free(names[i]);
  if (rc == D2KU_OK && to >= 0)
    rc = syncfd(c, to);
  return rc;
}
static d2ku_rc digest(d2ku_ctx *c, int d, unsigned char out[32]) {
  EVP_MD_CTX *h = EVP_MD_CTX_new();
  if (!h)
    return D2KU_IO;
  unsigned n = 0;
  d2ku_rc r =
      EVP_DigestInit_ex(h, EVP_sha256(), NULL) ? tree(c, d, -1, h, 0) : D2KU_IO;
  if (r == D2KU_OK && (!EVP_DigestFinal_ex(h, out, &n) || n != 32))
    r = D2KU_IO;
  EVP_MD_CTX_free(h);
  return r;
}
static void hex(const unsigned char *p, char out[65]) {
  static const char h[] = "0123456789abcdef";
  for (unsigned i = 0; i < 32; i++) {
    out[2 * i] = h[p[i] >> 4];
    out[2 * i + 1] = h[p[i] & 15];
  }
  out[64] = 0;
}
static int marker_bytes(char out[384], const char *id, const char *seal,
                        const char *input, uint64_t bits,
                        d2ku_source_kind kind) {
  int n = snprintf(out, 384, "D2KB2 %u %s %s %s %llu", (unsigned)kind, id, seal,
                   input, (unsigned long long)bits);
  unsigned char hash[32];
  unsigned len = 0;
  char h[65];
  if (n < 0 || n > 300 ||
      !EVP_Digest(out, (size_t)n, hash, &len, EVP_sha256(), NULL) || len != 32)
    return -1;
  hex(hash, h);
  return n + snprintf(out + n, 384 - (size_t)n, " %s\n", h);
}
static d2ku_rc marker_read(int at, const char *name, char id[65], char seal[65],
                           char input[65], uint64_t *bits,
                           d2ku_source_kind *kind) {
  int fd = openat(at, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  char b[384] = {0}, sum[65], extra, canonical[384];
  struct stat st;
  ssize_t n = -1;
  if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
      st.st_uid == geteuid() && !(st.st_mode & 077) &&
      st.st_size < (off_t)sizeof b)
    n = read(fd, b, sizeof b - 1);
  close(fd);
  unsigned long long mask;
  unsigned source;
  if (n <= 0 ||
      sscanf(b, "D2KB2 %u %64s %64s %64s %llu %64s %c", &source, id, seal,
             input, &mask, sum, &extra) != 6 ||
      source > 1 || !d2k_runtime_id_valid(id) || strlen(seal) != 64 ||
      strspn(seal, "0123456789abcdef") != 64 || strlen(input) != 64 ||
      strspn(input, "0123456789abcdef") != 64 || mask > 15)
    return D2KU_RECOVERY;
  int want =
      marker_bytes(canonical, id, seal, input, mask, (d2ku_source_kind)source);
  if (want != n || memcmp(b, canonical, (size_t)n))
    return D2KU_RECOVERY;
  *bits = mask;
  *kind = (d2ku_source_kind)source;
  return D2KU_OK;
}
static d2ku_rc old_runtime_check(d2ku_ctx *c, int saved, char release[65]) {
  release[0] = 0;
  for (unsigned i = 0; i < 4; i++) {
    int pipefd[2];
    if (pipe(pipefd))
      return D2KU_IO;
    pid_t p = fork();
    if (p < 0) {
      close(pipefd[0]);
      close(pipefd[1]);
      return D2KU_IO;
    }
    if (!p) {
      setpgid(0, 0);
      close(pipefd[0]);
      if (dup2(pipefd[1], 1) < 0 || fchdir(saved))
        _exit(126);
      close(pipefd[1]);
      close(3);
      close(4);
      close(5);
      execl(bins[i], bins[i], "--self-check", (char *)NULL);
      _exit(127);
    }
    setpgid(p, p);
    close(pipefd[1]);
    char out[256] = {0};
    size_t used = 0;
    int status = 0, exited = 0;
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    for (unsigned ticks = 0; ticks < 500; ticks++) {
      ssize_t n = read(pipefd[0], out + used, sizeof out - 1 - used);
      if (n > 0)
        used += (size_t)n;
      if (waitpid(p, &status, WNOHANG) == p) {
        exited = 1;
        while (used < sizeof out - 1 &&
               (n = read(pipefd[0], out + used, sizeof out - 1 - used)) > 0)
          used += (size_t)n;
        break;
      }
      if (used == sizeof out - 1)
        break;
      struct timespec t = {0, 10000000};
      nanosleep(&t, NULL);
    }
    close(pipefd[0]);
    kill(-p, SIGKILL);
    if (!exited)
      while (waitpid(p, &status, 0) < 0 && errno == EINTR) {
      }
    if (!exited || !WIFEXITED(status) || WEXITSTATUS(status))
      return D2KU_INCOMPATIBLE;
    char *start = strstr(out, " self-check=ok release="),
         *end = strstr(out, " wire=13\n");
    if (!start || !end || end[9])
      return D2KU_INCOMPATIBLE;
    start += 23;
    size_t len = (size_t)(end - start);
    if (end <= start || len > 64)
      return D2KU_INCOMPATIBLE;
    char id[65];
    memcpy(id, start, len);
    id[len] = 0;
    if (!d2k_runtime_id_valid(id))
      return D2KU_INCOMPATIBLE;
    if (i && strcmp(release, id))
      return D2KU_INCOMPATIBLE;
    strcpy(release, id);
  }
  return c->transaction.offline
             ? c->transaction.offline(c->transaction.arg, saved, release)
             : D2KU_OK;
}
/* No symlink traversal in the external prefix: callers open /opt once and all
 * target parents below it are checked independently. */
static int initdir(d2ku_ctx *c) {
  int etc = dir(c, c->bootstrap_prefix_fd, "etc", 0);
  if (etc < 0)
    return -1;
  int d = dir(c, etc, "init.d", 0);
  close(etc);
  return d;
}
static int ndmdir(d2ku_ctx *c) {
  int etc = dir(c, c->bootstrap_prefix_fd, "etc", 0);
  if (etc < 0)
    return -1;
  int ndm = dir(c, etc, "ndm", 0);
  close(etc);
  if (ndm < 0)
    return -1;
  int d = dir(c, ndm, "netfilter.d", 0);
  close(ndm);
  return d;
}
d2ku_rc d2ku_bootstrap(d2ku_ctx *c, d2ku_status *status) {
  (void)status;
  if (!c || !c->transaction.capture || !c->transaction.services)
    return D2KU_INVALID;
  int lock = -1;
  d2ku_rc r = d2ku_maintenance_lock(c, &lock);
  if (r != D2KU_OK)
    return r;
  c->maintenance_lock_fd = lock;
  int up = -1, saved = -1, boot = -1, state = -1, rel = -1, releases = -1,
      sbin = -1, init = -1, ndm = -1, input = -1;
  uint64_t bits = 0;
  d2ku_source_kind kind = D2KU_SOURCE_RUNTIME;
  char legacy_abi[9] = "";
  char id[65], seal[65], inputseal[65], got[65], pending[384];
  unsigned char hash[32];
  state = dir(c, c->root_dirfd, "update-state", 0);
  if (state < 0) {
    r = D2KU_IO;
    goto end;
  }
  r = marker_read(state, "bootstrap.done", id, seal, inputseal, &bits, &kind);
  if (r == D2KU_OK) {
    r = syncfd(c, state);
    goto end;
  }
  if (r != D2KU_ABSENT)
    goto end;
  up = dir(c, c->root_dirfd, "update", 1);
  if (up < 0) {
    r = D2KU_IO;
    goto end;
  }
  saved = dir(c, up, "legacy-flat", 1);
  boot = dir(c, c->root_dirfd, "boot", 1);
  releases = dir(c, c->root_dirfd, "releases", 1);
  sbin = dir(c, c->bootstrap_prefix_fd, "sbin", 0);
  init = initdir(c);
  ndm = ndmdir(c);
  if (saved < 0 || boot < 0 || releases < 0 || sbin < 0 || init < 0 ||
      ndm < 0) {
    r = D2KU_IO;
    goto end;
  }
  r = marker_read(state, "bootstrap.pending", id, seal, inputseal, &bits,
                  &kind);
  if (r == D2KU_ABSENT) {
    /* Inventory validation completes before any service stop or entry
     * replacement. */
    r = c->transaction.capture(c->transaction.arg, &bits);
    if (r != D2KU_OK || bits > 15)
      goto end;
    for (unsigned i = 0; i < 4; i++) {
      r = copy_file(c, sbin, bins[i], saved, bins[i]);
      if (r != D2KU_OK)
        goto end;
    }
    r = old_runtime_check(c, saved, id);
    if (r == D2KU_INCOMPATIBLE) {
      r = d2ku_legacy_admit(c, saved, legacy_abi);
      if (r == D2KU_OK)
        r = d2ku_legacy_bind(c, saved);
      if (r == D2KU_OK)
        kind = D2KU_SOURCE_LEGACY_LOCAL;
    }
    if (r != D2KU_OK)
      goto end;
    for (unsigned i = 0; i < 7; i++) {
      r = copy_file(c, c->root_dirfd, helpers[i], saved, helpers[i]);
      if (r != D2KU_OK)
        goto end;
    }
    r = copy_file(c, init, "S99d2k", saved, "flat-S99d2k");
    if (r != D2KU_OK)
      goto end;
    r = copy_file(c, ndm, "001-d2k.sh", saved, "flat-001-d2k.sh");
    if (r != D2KU_OK)
      goto end;
    r = kind == D2KU_SOURCE_RUNTIME
            ? copy_file(c, c->root_dirfd, "config", saved, "flat-config")
            : D2KU_OK;
    if (r != D2KU_OK)
      goto end;
    const char *dirs[] = {"panel", "files"};
    for (unsigned i = 0; i < 2; i++) {
      int a = dir(c, c->root_dirfd, dirs[i], 0), b = dir(c, saved, dirs[i], 1);
      r = a < 0 || b < 0 ? D2KU_INVALID : D2KU_OK;
      if (r == D2KU_OK && kind == D2KU_SOURCE_LEGACY_LOCAL)
        r = source_names(c, a, 0);
      if (r == D2KU_OK)
        r = tree(c, a, b, NULL, 0);
      if (a >= 0)
        close(a);
      if (b >= 0)
        close(b);
      if (r != D2KU_OK)
        goto end;
    }
    /* Copy bootstrap inputs to private stable storage; recovery never needs the
     * original installer temp directory after publishing pending. */
    input = dir(c, boot, "input", 1);
    if (input < 0) {
      r = D2KU_IO;
      goto end;
    }
    for (unsigned i = 0; i < sizeof bundle / sizeof *bundle; i++) {
      r = copy_file(c, c->bootstrap_bundle_fd, bundle[i], input, bundle[i]);
      if (r != D2KU_OK)
        goto end;
    }
    const char *first_files[] = {"d2k-update-first", "update.conf"};
    struct stat first_stat;
    int has_first = fstatat(c->bootstrap_bundle_fd, "d2k-update-first",
                            &first_stat, AT_SYMLINK_NOFOLLOW) == 0;
    int has_config = fstatat(c->bootstrap_bundle_fd, "update.conf", &first_stat,
                             AT_SYMLINK_NOFOLLOW) == 0;
    if (has_first != has_config) {
      r = D2KU_INVALID;
      goto end;
    }
    if (has_first)
      for (unsigned k = 0; k < 2; k++) {
        r = copy_file(c, c->bootstrap_bundle_fd, first_files[k], input,
                      first_files[k]);
        if (r == D2KU_OK)
          r = copy_file(c, input, first_files[k], boot, first_files[k]);
        if (r != D2KU_OK)
          goto end;
      }
    for (unsigned i = 0; i < 7; i++) {
      r = copy_file(c, c->bootstrap_bundle_fd, helpers[i], input, helpers[i]);
      if (r != D2KU_OK)
        goto end;
    }
    for (unsigned i = 0; i < 2; i++) {
      r = copy_file(c, input, bundle[i], boot, bundle[i]);
      if (r != D2KU_OK)
        goto end;
    }
    r = copy_file(c, input, "uninstall.sh", boot, "uninstall.sh");
    if (r != D2KU_OK)
      goto end;
    if (kind == D2KU_SOURCE_LEGACY_LOCAL) {
      r = clean_temps(c, saved, 0);
      if (r != D2KU_OK)
        goto end;
    }
    r = kind == D2KU_SOURCE_LEGACY_LOCAL ? d2ku_legacy_hash(saved, hash)
                                         : digest(c, saved, hash);
    if (r != D2KU_OK)
      goto end;
    hex(hash, seal);
    if (kind == D2KU_SOURCE_LEGACY_LOCAL)
      snprintf(id, sizeof id, "legacy-local-%.32s", seal);
    /* Keep the verified runtime identity: recovery checks both this ID and
     * the preserved executable inode; the receipt separately seals inventory.
     */
    /* Early recovery hook is durable before pending/any destructive phase. */
    r = copy_file(c, input, "S98d2k-update", init, "S98d2k-update");
    if (r != D2KU_OK)
      goto end;
    r = digest(c, input, hash);
    if (r != D2KU_OK)
      goto end;
    hex(hash, inputseal);
    int n = marker_bytes(pending, id, seal, inputseal, bits, kind);
    if (n < 0) {
      r = D2KU_IO;
      goto end;
    }
    r = atomic(c, state, "bootstrap.pending", pending, (size_t)n, 0600);
    if (r != D2KU_OK)
      goto end;
  } else if (r != D2KU_OK)
    goto end;
  if (input < 0)
    input = dir(c, boot, "input", 0);
  if (input < 0) {
    r = D2KU_IO;
    goto end;
  }
  r = digest(c, input, hash);
  if (r != D2KU_OK)
    goto end;
  hex(hash, got);
  if (strcmp(got, inputseal)) {
    r = D2KU_RECOVERY;
    goto end;
  }
  r = kind == D2KU_SOURCE_LEGACY_LOCAL ? d2ku_legacy_hash(saved, hash)
                                       : digest(c, saved, hash);
  if (r != D2KU_OK)
    goto end;
  hex(hash, got);
  if (strcmp(got, seal)) {
    r = D2KU_RECOVERY;
    goto end;
  }
  rel = dir(c, releases, id, 1);
  if (rel < 0) {
    r = D2KU_IO;
    goto end;
  }
  for (unsigned i = 0; i < 4; i++) {
    r = copy_file(c, saved, bins[i], rel, bins[i]);
    if (r != D2KU_OK)
      goto end;
  }
  for (unsigned i = 0; i < 7; i++) {
    r = copy_file(c, input, helpers[i], rel, helpers[i]);
    if (r != D2KU_OK)
      goto end;
  }
  r = copy_file(c, input, "S99d2k", rel, "S99d2k");
  if (r != D2KU_OK)
    goto end;
  const char *dirs[] = {"panel", "files"};
  for (unsigned i = 0; i < 2; i++) {
    int a = dir(c, saved, dirs[i], 0), b = dir(c, rel, dirs[i], 1);
    r = a < 0 || b < 0 ? D2KU_INVALID : tree(c, a, b, NULL, 0);
    if (a >= 0)
      close(a);
    if (b >= 0)
      close(b);
    if (r != D2KU_OK)
      goto end;
  }
  /* Legacy preparation never stops/restarts old runtimes or snapshots live
   * personal data. The first authenticated transaction owns that boundary. */
  if (kind == D2KU_SOURCE_LEGACY_LOCAL) {
    r = clean_temps(c, rel, 0);
    if (r == D2KU_OK)
      r = d2ku_legacy_admit(c, saved, legacy_abi);
    if (r == D2KU_OK)
      r = d2ku_legacy_create(c, saved, rel, id, legacy_abi, hash);
    if (r == D2KU_OK)
      r = d2ku_legacy_source(c, id, hash);
    if (r != D2KU_OK)
      goto end;
  }
  /* Receipt is idempotent only for this sealed local inventory. */
  char receipt[160];
  int n = snprintf(receipt, sizeof receipt, "D2KR1 13 1 1 %s\n", seal);
  r = kind == D2KU_SOURCE_RUNTIME
          ? atomic(c, rel, ".d2ku-receipt", receipt, (size_t)n, 0600)
          : D2KU_OK;
  if (r != D2KU_OK)
    goto end;
  /* All externally writable helpers become fixed lifecycle entries. */
  r = copy_file(c, input, "S99d2k", init, "S99d2k");
  if (r != D2KU_OK)
    goto end;
  r = copy_file(c, input, "001-d2k.sh", ndm, "001-d2k.sh");
  if (r != D2KU_OK)
    goto end;
  for (unsigned i = 0; i < 7; i++) {
    r = copy_file(c, input, helpers[i], c->root_dirfd, helpers[i]);
    if (r != D2KU_OK)
      goto end;
  }
  if (kind == D2KU_SOURCE_RUNTIME) {
    r = c->transaction.services(c->transaction.arg, "stop", id, bits);
    if (r != D2KU_OK)
      goto end;
    /* No personal mutation occurs during migration. Retain a quiesced backup in
     * addition to untouched live data, including files first written on stop.
     */
    int personal = dir(c, up, "legacy-personal", 1);
    if (personal < 0) {
      r = D2KU_IO;
      goto end;
    }
    for (size_t i = 0; i < c->transaction.path_count && r == D2KU_OK; i++) {
      const char *name = c->transaction.paths[i].name;
      struct stat st;
      if (fstatat(c->root_dirfd, name, &st, AT_SYMLINK_NOFOLLOW)) {
        if (errno == ENOENT)
          continue;
        r = D2KU_IO;
        break;
      }
      if (S_ISDIR(st.st_mode)) {
        int a = dir(c, c->root_dirfd, name, 0), b = dir(c, personal, name, 1);
        r = a < 0 || b < 0 ? D2KU_INVALID : tree(c, a, b, NULL, 0);
        if (a >= 0)
          close(a);
        if (b >= 0)
          close(b);
      } else
        r = copy_file(c, c->root_dirfd, name, personal, name);
    }
    close(personal);
    if (r != D2KU_OK)
      goto end;
  }
  char target[100];
  snprintf(target, sizeof target, "releases/%s", id);
  unlinkat(c->root_dirfd, ".bootstrap-current", 0);
  if (symlinkat(target, c->root_dirfd, ".bootstrap-current") ||
      renameat(c->root_dirfd, ".bootstrap-current", c->root_dirfd, "current")) {
    r = D2KU_IO;
    goto end;
  }
  r = syncfd(c, c->root_dirfd);
  if (r != D2KU_OK)
    goto end;
  /* Stable binary launchers never traverse current a second time. */
  for (unsigned i = 0; i < 4; i++) {
    char script[256];
    n = snprintf(script, sizeof script,
                 "#!/bin/sh\nexec /opt/d2k/boot/d2k-service-adapter --launch "
                 "%s \"$@\"\n",
                 bins[i]);
    r = atomic(c, sbin, bins[i], script, (size_t)n, 0755);
    if (r != D2KU_OK)
      goto end;
  }
  const char launcher[] =
      "#!/bin/sh\nexec /opt/d2k/boot/d2k-service-adapter service \"$@\"\n";
  r = atomic(c, sbin, "d2k", launcher, sizeof launcher - 1, 0755);
  if (r != D2KU_OK)
    goto end;
  char mask[24];
  n = snprintf(mask, sizeof mask, "%llu\n", (unsigned long long)bits);
  r = atomic(c, state, "enabled", mask, (size_t)n, 0600);
  if (r != D2KU_OK)
    goto end;
  r = kind == D2KU_SOURCE_RUNTIME
          ? c->transaction.services(c->transaction.arg, "start", id, bits)
          : D2KU_OK;
  if (r != D2KU_OK)
    goto end;
  if (renameat(state, "bootstrap.pending", state, "bootstrap.done")) {
    r = D2KU_IO;
    goto end;
  }
  r = syncfd(c, state);
end: {
  int fds[] = {input, ndm, init, sbin, rel, releases, state, boot, saved, up};
  for (unsigned i = 0; i < sizeof fds / sizeof *fds; i++)
    if (fds[i] >= 0)
      close(fds[i]);
}
  c->maintenance_lock_fd = -1;
  close(lock);
  return r;
}

/* First-worker fallback is bound to the preserved bootstrap inventory, not to
 * the absence of an updater binary in an arbitrary signed release. */
static int equal_file(int a, int b, const char *name) {
  int x = openat(a, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC),
      y = openat(b, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  struct stat sx, sy;
  int good = x >= 0 && y >= 0 && !fstat(x, &sx) && !fstat(y, &sy) &&
             S_ISREG(sx.st_mode) && S_ISREG(sy.st_mode) &&
             sx.st_uid == geteuid() && sy.st_uid == geteuid() &&
             !(sx.st_mode & 022) && !(sy.st_mode & 022) &&
             sx.st_size == sy.st_size;
  char bx[4096], by[4096];
  while (good) {
    ssize_t nx = read(x, bx, sizeof bx), ny = read(y, by, sizeof by);
    if (nx < 0 || ny != nx || memcmp(bx, by, nx > 0 ? (size_t)nx : 0)) {
      good = 0;
      break;
    }
    if (!nx)
      break;
  }
  if (x >= 0)
    close(x);
  if (y >= 0)
    close(y);
  return good;
}
d2ku_rc d2ku_bootstrap_first(d2ku_ctx *c) {
  int state = dir(c, c->root_dirfd, "update-state", 0);
  if (state < 0)
    return D2KU_ABSENT;
  struct stat st;
  if (!fstatat(state, "first-retired", &st, AT_SYMLINK_NOFOLLOW)) {
    close(state);
    return D2KU_INCOMPATIBLE;
  }
  char id[65], oldseal[65], inputseal[65], current[65], actual[65];
  uint64_t bits;
  d2ku_source_kind kind;
  d2ku_rc r = marker_read(state, "bootstrap.done", id, oldseal, inputseal,
                          &bits, &kind);
  close(state);
  if (r != D2KU_OK)
    return r;
  r = d2ku_tx_current(c, current);
  if (r != D2KU_OK || strcmp(id, current))
    return D2KU_INCOMPATIBLE;
  d2ku_journal journal;
  r = d2ku_journal_load(c, &journal);
  if (r != D2KU_ABSENT && (r != D2KU_OK || journal.phase != D2KU_ROLLED_BACK ||
                           strcmp(journal.old_release_id, id)))
    return D2KU_INCOMPATIBLE;
  unsigned char hash[32];
  r = d2ku_tx_receipt(c, id, hash);
  if (r != D2KU_OK)
    return r;
  hex(hash, actual);
  if (strcmp(actual, oldseal))
    return D2KU_RECOVERY;
  int boot = dir(c, c->root_dirfd, "boot", 0),
      input = boot >= 0 ? dir(c, boot, "input", 0) : -1;
  if (input < 0) {
    if (boot >= 0)
      close(boot);
    return D2KU_ABSENT;
  }
  r = digest(c, input, hash);
  hex(hash, actual);
  if (r == D2KU_OK && strcmp(actual, inputseal))
    r = D2KU_RECOVERY;
  if (r == D2KU_OK && (!equal_file(boot, input, "d2k-update-first") ||
                       !equal_file(boot, input, "update.conf")))
    r = D2KU_UNTRUSTED;
  close(input);
  close(boot);
  return r;
}
d2ku_rc d2ku_bootstrap_retire_first(d2ku_ctx *c) {
  int lock = -1;
  d2ku_rc r = d2ku_maintenance_lock(c, &lock);
  if (r != D2KU_OK)
    return r;
  d2ku_journal j;
  r = d2ku_journal_load(c, &j);
  if (r == D2KU_ABSENT) {
    d2ku_maintenance_unlock(lock);
    return D2KU_OK;
  }
  if (r == D2KU_OK && j.phase == D2KU_COMMITTED) {
    int state = dir(c, c->root_dirfd, "update-state", 0);
    if (state < 0)
      r = D2KU_IO;
    else {
      r = atomic(c, state, "first-retired", "D2KF1\n", 6, 0600);
      close(state);
    }
  }
  d2ku_maintenance_unlock(lock);
  return r;
}
