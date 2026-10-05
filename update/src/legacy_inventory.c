#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../../runtime/d2k_runtime.h"
#include "legacy.h"
#include <dirent.h>
#include <errno.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <unistd.h>
static int safe(int f, int directory) {
  struct stat s;
  return f >= 0 && !fstat(f, &s) && s.st_uid == geteuid() &&
         !(s.st_mode & 022) &&
         (directory ? S_ISDIR(s.st_mode)
                    : (S_ISREG(s.st_mode) && s.st_nlink == 1));
}
static int dir(int at, const char *p) {
  int f = openat(at, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (!safe(f, 1)) {
    if (f >= 0)
      close(f);
    return -1;
  }
  return f;
}
static int cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}
static d2ku_rc tree(int at, EVP_MD_CTX *h, unsigned depth, size_t *files) {
  if (depth > 12)
    return D2KU_INVALID;
  int dupfd = dup(at);
  if (dupfd < 0)
    return D2KU_IO;
  DIR *d = fdopendir(dupfd);
  if (!d) {
    close(dupfd);
    return D2KU_IO;
  }
  rewinddir(d);
  char *names[1024];
  size_t n = 0;
  struct dirent *e;
  d2ku_rc rc = D2KU_OK;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") ||
        (!depth && !strcmp(e->d_name, ".d2ku-legacy")))
      continue;
    if (n == 1024 || ++*files > 4096) {
      rc = D2KU_INVALID;
      break;
    }
    names[n] = strdup(e->d_name);
    if (!names[n]) {
      rc = D2KU_IO;
      break;
    }
    n++;
  }
  closedir(d);
  qsort(names, n, sizeof *names, cmp);
  for (size_t i = 0; i < n && rc == D2KU_OK; i++) {
    struct stat s, before, after;
    if (fstatat(at, names[i], &s, AT_SYMLINK_NOFOLLOW) ||
        s.st_uid != geteuid() || (s.st_mode & 022)) {
      rc = D2KU_INVALID;
      break;
    }
    EVP_DigestUpdate(h, names[i], strlen(names[i]) + 1);
    if (S_ISDIR(s.st_mode)) {
      char mode[24];
      int count =
          snprintf(mode, sizeof mode, "D%u:", (unsigned)(s.st_mode & 0777));
      EVP_DigestUpdate(h, mode, (size_t)count);
      int sub = dir(at, names[i]);
      rc = sub < 0 ? D2KU_INVALID : tree(sub, h, depth + 1, files);
      if (sub >= 0)
        close(sub);
      EVP_DigestUpdate(h, "E", 1);
    } else if (S_ISREG(s.st_mode) && s.st_nlink == 1 && s.st_size >= 0 &&
               s.st_size <= 128 * 1024 * 1024) {
      int f =
          openat(at, names[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
      if (!safe(f, 0) || fstat(f, &before) || before.st_ino != s.st_ino ||
          before.st_dev != s.st_dev) {
        if (f >= 0)
          close(f);
        rc = D2KU_INVALID;
        break;
      }
      char meta[80], b[16384];
      int z =
          snprintf(meta, sizeof meta, "F%u:%llu:", (unsigned)(s.st_mode & 0777),
                   (unsigned long long)s.st_size);
      EVP_DigestUpdate(h, meta, (size_t)z);
      ssize_t k;
      off_t total = 0;
      while ((k = read(f, b, sizeof b)) > 0) {
        EVP_DigestUpdate(h, b, (size_t)k);
        total += k;
      }
      if (k < 0 || fstat(f, &after) || total != s.st_size ||
          before.st_size != after.st_size ||
          before.st_mtime != after.st_mtime || before.st_ctime != after.st_ctime
#ifdef __APPLE__
          || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
          before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec
#else
          || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
          before.st_ctim.tv_nsec != after.st_ctim.tv_nsec
#endif
      )
        rc = D2KU_IO;
      close(f);
    } else
      rc = D2KU_INVALID;
  }
  for (size_t i = 0; i < n; i++)
    free(names[i]);
  return rc;
}
d2ku_rc d2ku_legacy_hash(int at, unsigned char hash[32]) {
  if (!safe(at, 1))
    return D2KU_INVALID;
  EVP_MD_CTX *h = EVP_MD_CTX_new();
  if (!h)
    return D2KU_IO;
  size_t files = 0;
  unsigned n = 0;
  d2ku_rc rc = EVP_DigestInit_ex(h, EVP_sha256(), NULL) ? tree(at, h, 0, &files)
                                                        : D2KU_IO;
  if (rc == D2KU_OK && (!EVP_DigestFinal_ex(h, hash, &n) || n != 32))
    rc = D2KU_IO;
  EVP_MD_CTX_free(h);
  return rc;
}
static void hex(const unsigned char *h, char *s) {
  for (unsigned i = 0; i < 32; i++)
    snprintf(s + 2 * i, 3, "%02x", h[i]);
}
static int unhex(const char *s, unsigned char *h) {
  if (strlen(s) != 64 || strspn(s, "0123456789abcdef") != 64)
    return 0;
  for (unsigned i = 0; i < 32; i++) {
    unsigned v;
    if (sscanf(s + 2 * i, "%2x", &v) != 1)
      return 0;
    h[i] = (unsigned char)v;
  }
  return 1;
}
static d2ku_rc syncfd(d2ku_ctx *c, int fd) {
  return c->sync_fd ? c->sync_fd(c->io_arg, fd)
                    : (fsync(fd) ? D2KU_IO : D2KU_OK);
}
static d2ku_rc write_atomic(d2ku_ctx *c, int at, const char *name,
                            const char *body) {
  char tmp[80];
  snprintf(tmp, sizeof tmp, ".legacy-%ld", (long)getpid());
  int fd = openat(at, tmp, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY | O_CLOEXEC,
                  0600);
  if (fd < 0)
    return D2KU_IO;
  size_t n = strlen(body);
  d2ku_rc rc = write(fd, body, n) == (ssize_t)n ? syncfd(c, fd) : D2KU_IO;
  close(fd);
  if (rc == D2KU_OK && renameat(at, tmp, at, name))
    rc = D2KU_IO;
  if (rc == D2KU_OK)
    rc = syncfd(c, at);
  if (rc != D2KU_OK)
    unlinkat(at, tmp, 0);
  return rc;
}
static d2ku_rc read_record(int at, const char *name, char body[512]) {
  int f = openat(at, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (f < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  struct stat s;
  ssize_t n = -1;
  if (safe(f, 0) && !fstat(f, &s) && !(s.st_mode & 077) && s.st_size > 0 &&
      s.st_size < 512)
    n = read(f, body, 511);
  close(f);
  if (n <= 0)
    return D2KU_RECOVERY;
  body[n] = 0;
  return D2KU_OK;
}
static int abi_valid(const char *s) {
  const char *all[] = {"arm64", "arm",      "amd64", "x86",    "mipsel",
                       "mips",  "mips64el", "ppc64", "riscv64"};
  for (unsigned i = 0; i < 9; i++)
    if (!strcmp(s, all[i]))
      return 1;
  return 0;
}
static int bytes(char out[512], const char *id, const char *abi,
                 const char *old, const char *release, const char *resources) {
  int n = snprintf(out, 512, "D2KV1 flat-wire12-2026-10-04 %s %s %s %s %s", id,
                   abi, old, release, resources);
  unsigned char hash[32];
  unsigned size = 0;
  char h[65];
  if (n < 0 || n > 430 ||
      !EVP_Digest(out, (size_t)n, hash, &size, EVP_sha256(), NULL) ||
      size != 32)
    return 0;
  hex(hash, h);
  return n + snprintf(out + n, 512 - (size_t)n, " %s\n", h);
}
d2ku_rc d2ku_legacy_create(d2ku_ctx *c, int saved, int release, const char *id,
                           const char *abi, const unsigned char inventory[32]) {
  if (!d2k_runtime_id_valid(id) || !abi_valid(abi))
    return D2KU_INVALID;
  unsigned char h[32];
  char a[65], b[65], r[65], body[512];
  d2ku_rc rc = d2ku_legacy_hash(saved, h);
  if (rc != D2KU_OK || memcmp(h, inventory, 32))
    return D2KU_RECOVERY;
  hex(h, a);
  rc = d2ku_legacy_hash(release, h);
  if (rc != D2KU_OK)
    return rc;
  hex(h, b);
  int files = dir(release, "files");
  rc = d2ku_legacy_hash(files, h);
  if (files >= 0)
    close(files);
  if (rc != D2KU_OK)
    return rc;
  hex(h, r);
  if (!bytes(body, id, abi, a, b, r))
    return D2KU_INVALID;
  int state = dir(c->root_dirfd, "update-state");
  if (state < 0)
    return D2KU_IO;
  rc = write_atomic(c, release, ".d2ku-legacy", body);
  if (rc == D2KU_OK)
    rc = write_atomic(c, state, "legacy-source", body);
  close(state);
  return rc;
}
d2ku_rc d2ku_legacy_source(d2ku_ctx *c, const char *id,
                           unsigned char inventory[32]) {
  if (!c || !d2k_runtime_id_valid(id))
    return D2KU_INVALID;
  int releases = dir(c->root_dirfd, "releases");
  if (releases < 0)
    return D2KU_IO;
  int rel = dir(releases, id);
  close(releases);
  if (rel < 0)
    return D2KU_IO;
  char body[512], anchor[512], canonical[512], rid[65], abi[9], a[65], b[65],
      res[65], sum[65], extra;
  d2ku_rc rc = read_record(rel, ".d2ku-legacy", body);
  if (rc != D2KU_OK) {
    close(rel);
    return rc;
  }
  struct stat both;
  if (!fstatat(rel, ".d2ku-receipt", &both, AT_SYMLINK_NOFOLLOW) ||
      errno != ENOENT) {
    close(rel);
    return D2KU_RECOVERY;
  }
  int state = dir(c->root_dirfd, "update-state");
  rc = state < 0 ? D2KU_IO : read_record(state, "legacy-source", anchor);
  if (state >= 0)
    close(state);
  if (rc != D2KU_OK || strcmp(body, anchor) ||
      sscanf(body,
             "D2KV1 flat-wire12-2026-10-04 %64s %8s %64s %64s %64s %64s %c",
             rid, abi, a, b, res, sum, &extra) != 6 ||
      strcmp(rid, id) || !abi_valid(abi) ||
      (c->abi[0] && strcmp(c->abi, abi)) ||
      !bytes(canonical, rid, abi, a, b, res) || strcmp(canonical, body)) {
    close(rel);
    return D2KU_RECOVERY;
  }
  unsigned char h[32], want[32];
  if (!unhex(a, inventory) || !unhex(b, want)) {
    close(rel);
    return D2KU_RECOVERY;
  }
  rc = d2ku_legacy_hash(rel, h);
  close(rel);
  if (rc != D2KU_OK || memcmp(h, want, 32))
    return D2KU_RECOVERY;
  int up = dir(c->root_dirfd, "update"),
      saved = up < 0 ? -1 : dir(up, "legacy-flat");
  if (up >= 0)
    close(up);
  rc = d2ku_legacy_hash(saved, h);
  if (saved >= 0)
    close(saved);
  if (rc != D2KU_OK || memcmp(h, inventory, 32))
    return D2KU_RECOVERY;
  int files = dir(c->root_dirfd, "files");
  rc = d2ku_legacy_hash(files, h);
  if (files >= 0)
    close(files);
  if (rc != D2KU_OK || !unhex(res, want) || memcmp(h, want, 32))
    return D2KU_RECOVERY;
  return D2KU_OK;
}
