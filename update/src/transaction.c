#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
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
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

static int valid_id(const char *s) {
    size_t n = strnlen(s, D2KU_ID_MAX + 1);
    if (!n || n > D2KU_ID_MAX)
        return 0;
    for (size_t k = 0; k < n; k++) {
        unsigned char c = s[k];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              (k && (c == '.' || c == '_' || c == '-'))))
            return 0;
    }
    return 1;
}
static d2ku_rc syncfd(d2ku_ctx *c, int fd) {
    if (c->sync_fd)
        return c->sync_fd(c->io_arg, fd);
    int r;
    do {
        r = fsync(fd);
    } while (r && errno == EINTR);
    return r ? D2KU_IO : D2KU_OK;
}
static d2ku_rc rename_file(d2ku_ctx *c, int a, const char *x, int b,
                           const char *y) {
    return c->rename_at ? c->rename_at(c->io_arg, a, x, b, y)
                        : (renameat(a, x, b, y) ? D2KU_IO : D2KU_OK);
}
static d2ku_rc writeall(d2ku_ctx *c, int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len) {
        ssize_t n = c->write_fd ? c->write_fd(c->io_arg, fd, p, len)
                                : write(fd, p, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || (size_t)n > len)
            return D2KU_IO;
        p += n;
        len -= (size_t)n;
    }
    return D2KU_OK;
}
static int directory(int at, const char *p) {
    int d = openat(at, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (d < 0)
        return -1;
    if (fstat(d, &st) || st.st_uid != geteuid() || (st.st_mode & 022)) {
        close(d);
        return -1;
    }
    return d;
}
static int mkdir_sync(d2ku_ctx *c, int at, const char *p) {
    if (mkdirat(at, p, 0700) && errno != EEXIST)
        return -1;
    int d = directory(at, p);
    if (d >= 0 && syncfd(c, at) != D2KU_OK) {
        close(d);
        d = -1;
    }
    return d;
}
static int release_dir(d2ku_ctx *c, const char *id) {
    if (!valid_id(id))
        return -1;
    int d = directory(c->root_dirfd, "releases");
    if (d < 0)
        return -1;
    struct stat root_stat, release_stat;
    if (fstat(c->root_dirfd, &root_stat) || fstat(d, &release_stat) ||
        root_stat.st_dev != release_stat.st_dev) {
        close(d);
        return -1;
    }
    int r = directory(d, id);
    close(d);
    return r;
}
static d2ku_rc small_read(int dir, const char *name, char *b, size_t cap) {
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    struct stat st;
    if (fd < 0)
        return D2KU_IO;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_uid != geteuid() || st.st_size < 0 ||
        (uint64_t)st.st_size >= cap) {
        close(fd);
        return D2KU_IO;
    }
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, b + n, cap - 1 - n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            close(fd);
            return D2KU_IO;
        }
        if (!r)
            break;
        n += (size_t)r;
        if (n == cap - 1) {
            close(fd);
            return D2KU_IO;
        }
    }
    b[n] = 0;
    close(fd);
    return D2KU_OK;
}
static d2ku_rc new_file(d2ku_ctx *c, int d, const char *name, const void *b,
                        size_t n) {
    int fd = openat(d, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return D2KU_IO;
    d2ku_rc rc = writeall(c, fd, b, n);
    if (rc == D2KU_OK)
        rc = syncfd(c, fd);
    if (close(fd) && rc == D2KU_OK)
        rc = D2KU_IO;
    return rc;
}
static void hex(const unsigned char h[32], char s[65]) {
    const char *v = "0123456789abcdef";
    for (unsigned k = 0; k < 32; k++) {
        s[k * 2] = v[h[k] >> 4];
        s[k * 2 + 1] = v[h[k] & 15];
    }
    s[64] = 0;
}
static int unhex(const char *s, unsigned char h[32]) {
    if (strlen(s) != 64)
        return 0;
    for (unsigned k = 0; k < 32; k++) {
        unsigned v = 0;
        for (unsigned j = 0; j < 2; j++) {
            char c = s[k * 2 + j];
            if (c >= '0' && c <= '9')
                v = v * 16 + (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f')
                v = v * 16 + (unsigned)(c - 'a' + 10);
            else
                return 0;
        }
        h[k] = (unsigned char)v;
    }
    return 1;
}
static d2ku_rc receipt_write(d2ku_ctx *c, int d, const unsigned char hash[32]) {
    char b[256], h[65];
    hex(hash, h);
    int n = snprintf(b, sizeof b, "D2KR1 %llu %llu %llu %s\n",
                     (unsigned long long)c->wire_version,
                     (unsigned long long)c->state_version,
                     (unsigned long long)c->updater_version, h);
    d2ku_rc r = new_file(c, d, ".d2ku-receipt", b, (size_t)n);
    if (r == D2KU_OK)
        r = syncfd(c, d);
    return r;
}
d2ku_rc d2ku_release_receipt(d2ku_ctx *c, const char *id,
                             const unsigned char hash[32]) {
    int d = release_dir(c, id);
    if (d < 0)
        return D2KU_IO;
    d2ku_rc r = receipt_write(c, d, hash);
    close(d);
    return r;
}
d2ku_rc d2ku_tx_receipt(d2ku_ctx *c, const char *id, unsigned char hash[32]) {
  int d = release_dir(c, id);
  if (d < 0)
    return D2KU_IO;
  char b[256], h[65], tail;
  d2ku_rc r = small_read(d, ".d2ku-receipt", b, sizeof b);
  close(d);
  if (r != D2KU_OK)
    return r;
  unsigned long long w, s, u;
  if (sscanf(b, "D2KR1 %llu %llu %llu %64s %c", &w, &s, &u, h, &tail) != 4 ||
      !unhex(h, hash))
    return D2KU_RECOVERY;
  if (w != c->wire_version || s != c->state_version || u > c->updater_version)
    return D2KU_INCOMPATIBLE;
  return D2KU_OK;
}
d2ku_rc d2ku_tx_current(d2ku_ctx *c, char id[D2KU_ID_MAX + 1]) {
    char p[128];
    ssize_t n = readlinkat(c->root_dirfd, "current", p, sizeof p - 1);
    if (n < 0 || n >= (ssize_t)sizeof p - 1)
        return D2KU_RECOVERY;
    p[n] = 0;
    if (strncmp(p, "releases/", 9) || !valid_id(p + 9))
        return D2KU_RECOVERY;
    strcpy(id, p + 9);
    return D2KU_OK;
}
static d2ku_rc switch_current(d2ku_ctx *c, const char *id) {
    int d = release_dir(c, id);
    if (d < 0)
        return D2KU_IO;
    close(d);
    char p[96];
    snprintf(p, sizeof p, "releases/%s", id);
    if (unlinkat(c->root_dirfd, ".current-update", 0) && errno != ENOENT)
        return D2KU_IO;
    if (symlinkat(p, c->root_dirfd, ".current-update"))
        return D2KU_IO;
    d2ku_rc r = rename_file(c, c->root_dirfd, ".current-update", c->root_dirfd,
                            "current");
    if (r == D2KU_OK)
        r = syncfd(c, c->root_dirfd);
    return r;
}
static d2ku_rc service(d2ku_ctx *c, const char *action, const char *id,
                       uint64_t mask) {
    if (!c->transaction.services || mask & ~UINT64_C(15))
        return D2KU_INVALID;
    return c->transaction.services(c->transaction.arg, action, id, mask);
}
d2ku_rc d2ku_tx_phase(d2ku_ctx *c, d2ku_journal *j, d2ku_phase phase) {
    d2ku_journal actual;
    d2ku_rc r = d2ku_journal_load(c, &actual);
    if (r != D2KU_OK && r != D2KU_ABSENT)
        return r;
    uint64_t seq = r == D2KU_ABSENT ? 0 : actual.sequence;
    if (seq == UINT64_MAX)
        return D2KU_IO;
    j->sequence = seq + 1;
    j->phase = phase;
    uint64_t ns;
    if (c->clock.monotonic && c->clock.monotonic(c->clock.arg, &ns) == D2KU_OK)
        j->progress_mono_ms = ns / 1000000;
    return d2ku_journal_store(c, j);
}
static d2ku_rc wait_ms(d2ku_ctx *c, unsigned ms) {
    if (c->transaction.wait_ms)
        return c->transaction.wait_ms(c->transaction.arg, ms);
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000};
    while (nanosleep(&t, &t))
        if (errno != EINTR)
            return D2KU_IO;
    return D2KU_OK;
}
/* Personal snapshot trees have no links/special files. Bound depth rather than
 * bytes: space is measured from the actual tree, never a data-loss truncation.
 */
static d2ku_rc tree(d2ku_ctx *c, int src, const char *name, int dst,
                    unsigned depth, uint64_t *bytes, EVP_MD_CTX *hash) {
    if (depth > 64)
        return D2KU_INVALID;
    struct stat st;
    if (fstatat(src, name, &st, AT_SYMLINK_NOFOLLOW))
        return D2KU_IO;
    if (st.st_uid != geteuid() ||
        (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) ||
        (S_ISREG(st.st_mode) && st.st_nlink != 1))
        return D2KU_INVALID;
    if (hash) {
        unsigned char kind = S_ISDIR(st.st_mode) ? 'D' : 'F';
        unsigned char mode[2] = {(unsigned char)((st.st_mode & 0777) >> 8),
                                 (unsigned char)(st.st_mode & 0777)};
        if (EVP_DigestUpdate(hash, mode, sizeof mode) != 1)
            return D2KU_IO;
        if (EVP_DigestUpdate(hash, &kind, 1) != 1 ||
            EVP_DigestUpdate(hash, name, strlen(name) + 1) != 1)
            return D2KU_IO;
    }
    if (S_ISDIR(st.st_mode)) {
        int a = directory(src, name);
        if (a < 0)
            return D2KU_IO;
        int b = -1;
        if (dst >= 0) {
            if (mkdirat(dst, name, 0700)) {
                close(a);
                return D2KU_IO;
            }
            b = directory(dst, name);
            if (b < 0) {
                close(a);
                return D2KU_IO;
            }
        }
        DIR *dp = fdopendir(dup(a));
        if (!dp) {
            close(a);
            if (b >= 0)
                close(b);
            return D2KU_IO;
        }
        char **names = NULL;
        size_t count = 0;
        struct dirent *e;
        d2ku_rc r = D2KU_OK;
        for (;;) {
            errno = 0;
            e = readdir(dp);
            if (!e) {
                if (errno)
                    r = D2KU_IO;
                break;
            }
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            char **v = realloc(names, (count + 1) * sizeof *v);
            if (!v) {
                r = D2KU_IO;
                break;
            }
            names = v;
            names[count] = strdup(e->d_name);
            if (!names[count]) {
                r = D2KU_IO;
                break;
            }
            count++;
        }
        closedir(dp);
        for (size_t i = 0; i < count; i++)
            for (size_t j = i + 1; j < count; j++)
                if (strcmp(names[i], names[j]) > 0) {
                    char *x = names[i];
                    names[i] = names[j];
                    names[j] = x;
                }
        for (size_t k = 0; k < count; k++) {
            if (r == D2KU_OK)
                r = tree(c, a, names[k], b, depth + 1, bytes, hash);
            free(names[k]);
        }
        free(names);
        if (r == D2KU_OK && hash) {
            const unsigned char end_directory = 0xff;
            if (EVP_DigestUpdate(hash, &end_directory, 1) != 1)
                r = D2KU_IO;
        }
        if (r == D2KU_OK && b >= 0) {
            if (fchmod(b, st.st_mode & 0777))
                r = D2KU_IO;
            else
                r = syncfd(c, b);
        }
        if (b >= 0)
            close(b);
        close(a);
        return r;
    }
    if (st.st_size < 0 || UINT64_MAX - *bytes < (uint64_t)st.st_size)
        return D2KU_IO;
    *bytes += (uint64_t)st.st_size;
    if (hash) {
        unsigned char length[8];
        uint64_t size = (uint64_t)st.st_size;
        for (unsigned k = 0; k < 8; k++)
            length[7 - k] = (unsigned char)(size >> (8 * k));
        if (EVP_DigestUpdate(hash, length, sizeof length) != 1)
            return D2KU_IO;
    }
    int a = openat(src, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (a < 0)
        return D2KU_IO;
    struct stat opened;
    if (fstat(a, &opened) || opened.st_dev != st.st_dev ||
        opened.st_ino != st.st_ino) {
        close(a);
        return D2KU_IO;
    }
    int b = -1;
    if (dst >= 0) {
        b = openat(dst, name,
                   O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (b < 0) {
            close(a);
            return D2KU_IO;
        }
    }
    char buf[16384];
    uint64_t seen = 0;
    d2ku_rc r = D2KU_OK;
    for (;;) {
        ssize_t n = read(a, buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            r = D2KU_IO;
            break;
        }
        if (!n)
            break;
        seen += (uint64_t)n;
        if ((b >= 0 && writeall(c, b, buf, (size_t)n) != D2KU_OK) ||
            (hash && EVP_DigestUpdate(hash, buf, (size_t)n) != 1)) {
            r = D2KU_IO;
            break;
        }
    }
    if (seen != (uint64_t)st.st_size)
        r = D2KU_IO;
    if (hash) {
        char end[48];
        int n = snprintf(end, sizeof end, "/%llu/", (unsigned long long)seen);
        if (EVP_DigestUpdate(hash, end, (size_t)n) != 1)
            r = D2KU_IO;
    }
    if (r == D2KU_OK && b >= 0) {
        if (fchmod(b, st.st_mode & 0777))
            r = D2KU_IO;
        else
            r = syncfd(c, b);
    }
    if (b >= 0)
        close(b);
    close(a);
    return r;
}
static d2ku_rc remove_tree(int at, const char *name) {
    struct stat st;
    if (fstatat(at, name, &st, AT_SYMLINK_NOFOLLOW))
        return errno == ENOENT ? D2KU_OK : D2KU_IO;
    if (!S_ISDIR(st.st_mode))
        return unlinkat(at, name, 0) ? D2KU_IO : D2KU_OK;
    int d = directory(at, name);
    if (d < 0)
        return D2KU_IO;
    DIR *dp = fdopendir(dup(d));
    if (!dp) {
        close(d);
        return D2KU_IO;
    }
    d2ku_rc r = D2KU_OK;
    struct dirent *e;
    while ((e = readdir(dp)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..") &&
            remove_tree(d, e->d_name) != D2KU_OK) {
            r = D2KU_IO;
            break;
        }
    closedir(dp);
    close(d);
    if (r == D2KU_OK && unlinkat(at, name, AT_REMOVEDIR))
        r = D2KU_IO;
    return r;
}
static int personal_name(const char *p) {
    static const char *denied[] = {
        "update", "update-state", "releases", "current",   "boot",      "run",
        "logs",   "log",          "staging",  "snapshots", "inventory", "seal"};
    if (!valid_id(p))
        return 0;
    for (size_t k = 0; k < sizeof denied / sizeof *denied; k++)
        if (!strcmp(p, denied[k]))
            return 0;
    return 1;
}
static d2ku_rc paths_valid(d2ku_ctx *c) {
    if (!c->transaction.path_count ||
        c->transaction.path_count > D2KU_SNAPSHOT_PATHS_MAX)
        return D2KU_INVALID;
    for (size_t k = 0; k < c->transaction.path_count; k++) {
        d2ku_snapshot_path *p = &c->transaction.paths[k];
        if (!personal_name(p->name) ||
            (p->configuration != 0 && p->configuration != 1))
            return D2KU_INVALID;
        for (size_t n = 0; n < k; n++)
            if (!strcmp(p->name, c->transaction.paths[n].name))
                return D2KU_INVALID;
    }
    return D2KU_OK;
}
static d2ku_rc space(d2ku_ctx *c, const d2ku_manifest *m) {
    uint64_t n = 0;
    for (size_t k = 0; k < c->transaction.path_count; k++) {
        struct stat st;
        const char *p = c->transaction.paths[k].name;
        if (fstatat(c->root_dirfd, p, &st, AT_SYMLINK_NOFOLLOW)) {
            if (errno == ENOENT)
                continue;
            return D2KU_IO;
        }
        d2ku_rc r = tree(c, c->root_dirfd, p, -1, 0, &n, NULL);
        if (r != D2KU_OK)
            return r;
    }
    if (n > UINT64_MAX / 2)
        return D2KU_IO;
    n *= 2; /* snapshot and atomic restore copy */
    if (m) {
        if (m->package_count > D2KU_PACKAGES_MAX ||
            m->file_count > D2KU_FILES_MAX)
            return D2KU_INVALID;
        const d2ku_package *selected = NULL;
        for (size_t k = 0; k < m->package_count; k++)
            if (!strcmp(m->packages[k].abi, c->abi))
                selected = &m->packages[k];
        if (!selected || selected->file_offset > m->file_count ||
            selected->file_count > m->file_count - selected->file_offset)
            return D2KU_INCOMPATIBLE;
        for (size_t k = selected->file_offset;
             k < selected->file_offset + selected->file_count; k++) {
            if (UINT64_MAX - n < m->files[k].size)
                return D2KU_IO;
            n += m->files[k].size;
        }
    }
    if (c->transaction.available_bytes) {
        uint64_t available;
        d2ku_rc rc =
            c->transaction.available_bytes(c->transaction.arg, &available);
        return rc == D2KU_OK ? (available >= n ? D2KU_OK : D2KU_IO) : rc;
    }
    struct statvfs v;
    if (fstatvfs(c->root_dirfd, &v))
        return D2KU_IO;
    if (v.f_frsize && v.f_bavail > UINT64_MAX / v.f_frsize)
        return D2KU_OK;
    return (uint64_t)v.f_bavail * v.f_frsize >= n ? D2KU_OK : D2KU_IO;
}
static int snapshot_dir(d2ku_ctx *c, const char *id, int create) {
    int all = create ? mkdir_sync(c, c->root_dirfd, "snapshots")
                     : directory(c->root_dirfd, "snapshots");
    if (all < 0)
        return -1;
    int d = -1;
    if (create) {
        if (mkdirat(all, id, 0700) == 0) {
            d = directory(all, id);
            if (d >= 0 && syncfd(c, all) != D2KU_OK) {
                close(d);
                d = -1;
            }
        }
    } else
        d = directory(all, id);
    close(all);
    return d;
}
static d2ku_rc snapshot_begin(d2ku_ctx *c, d2ku_journal *j) {
    int d = snapshot_dir(c, j->transaction_id, 1);
    if (d < 0)
        return D2KU_IO;
    char list[2048];
    size_t n = 0;
    d2ku_rc r = D2KU_OK;
    for (size_t k = 0; k < c->transaction.path_count; k++) {
        d2ku_snapshot_path *p = &c->transaction.paths[k];
        struct stat st;
        int present =
            fstatat(c->root_dirfd, p->name, &st, AT_SYMLINK_NOFOLLOW) == 0;
        if (!present && errno != ENOENT) {
            r = D2KU_IO;
            break;
        }
        int z = snprintf(list + n, sizeof list - n, "%d %d %s\n",
                         p->configuration, present, p->name);
        if (z < 0 || (size_t)z >= sizeof list - n) {
            r = D2KU_INVALID;
            break;
        }
        n += (size_t)z;
        if (p->configuration && present) {
            uint64_t bytes = 0;
            r = tree(c, c->root_dirfd, p->name, d, 0, &bytes, NULL);
            if (r != D2KU_OK)
                break;
        }
    }
    if (r == D2KU_OK)
        r = new_file(c, d, "inventory", list, n);
    if (r == D2KU_OK)
        r = syncfd(c, d);
    close(d);
    return r;
}
static d2ku_rc inventory(int d, d2ku_snapshot_path p[D2KU_SNAPSHOT_PATHS_MAX],
                         int exists[D2KU_SNAPSHOT_PATHS_MAX], size_t *count) {
    char b[2048];
    d2ku_rc r = small_read(d, "inventory", b, sizeof b);
    if (r != D2KU_OK)
        return r;
    char *save = NULL;
    *count = 0;
    for (char *line = strtok_r(b, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (*count == D2KU_SNAPSHOT_PATHS_MAX)
            return D2KU_RECOVERY;
        char tail;
        size_t k = *count;
        if (sscanf(line, "%d %d %64s %c", &p[k].configuration, &exists[k],
                   p[k].name, &tail) != 3 ||
            !personal_name(p[k].name) || (exists[k] != 0 && exists[k] != 1) ||
            (p[k].configuration != 0 && p[k].configuration != 1))
            return D2KU_RECOVERY;
        for (size_t q = 0; q < k; q++)
            if (!strcmp(p[q].name, p[k].name))
                return D2KU_RECOVERY;
        (*count)++;
    }
    return *count ? D2KU_OK : D2KU_RECOVERY;
}
static d2ku_rc snapshot_hash(d2ku_ctx *c, int d, unsigned char h[32]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md)
        return D2KU_IO;
    d2ku_rc r = D2KU_IO;
    d2ku_snapshot_path p[D2KU_SNAPSHOT_PATHS_MAX];
    int present[D2KU_SNAPSHOT_PATHS_MAX];
    size_t n;
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1)
        goto out;
    r = inventory(d, p, present, &n);
    if (r != D2KU_OK)
        goto out;
    uint64_t bytes = 0;
    r = tree(c, d, "inventory", -1, 0, &bytes, md);
    for (size_t k = 0; r == D2KU_OK && k < n; k++) {
        if (present[k])
            r = tree(c, d, p[k].name, -1, 0, &bytes, md);
        else {
            struct stat st;
            if (!fstatat(d, p[k].name, &st, AT_SYMLINK_NOFOLLOW) ||
                errno != ENOENT)
                r = D2KU_RECOVERY;
        }
    }
    unsigned len;
    if (r == D2KU_OK && (EVP_DigestFinal_ex(md, h, &len) != 1 || len != 32))
        r = D2KU_IO;
out:
    EVP_MD_CTX_free(md);
    return r;
}
static d2ku_rc snapshot_finish(d2ku_ctx *c, d2ku_journal *j) {
    int d = snapshot_dir(c, j->transaction_id, 0);
    if (d < 0)
        return D2KU_IO;
    d2ku_snapshot_path p[D2KU_SNAPSHOT_PATHS_MAX];
    int present[D2KU_SNAPSHOT_PATHS_MAX];
    size_t n;
    d2ku_rc r = inventory(d, p, present, &n);
    char list[2048];
    size_t used = 0;
    for (size_t k = 0; r == D2KU_OK && k < n; k++) {
        if (!p[k].configuration) {
            struct stat st;
            present[k] = fstatat(c->root_dirfd, p[k].name, &st,
                                 AT_SYMLINK_NOFOLLOW) == 0;
            if (!present[k] && errno != ENOENT) {
                r = D2KU_IO;
                break;
            }
            if (present[k]) {
                uint64_t bytes = 0;
                r = tree(c, c->root_dirfd, p[k].name, d, 0, &bytes, NULL);
            }
        }
        int z = snprintf(list + used, sizeof list - used, "%d %d %s\n",
                         p[k].configuration, present[k], p[k].name);
        if (z < 0 || (size_t)z >= sizeof list - used) {
            r = D2KU_INVALID;
            break;
        }
        used += (size_t)z;
    }
    if (r == D2KU_OK)
        r = new_file(c, d, ".inventory", list, used);
    if (r == D2KU_OK)
        r = rename_file(c, d, ".inventory", d, "inventory");
    if (r == D2KU_OK)
        r = syncfd(c, d);
    unsigned char h[32];
    char hs[65];
    if (r == D2KU_OK)
        r = snapshot_hash(c, d, h);
    if (r == D2KU_OK) {
        hex(h, hs);
        r = new_file(c, d, "seal", hs, 64);
    }
    if (r == D2KU_OK)
        r = syncfd(c, d);
    close(d);
    if (r == D2KU_OK)
        j->snapshot_ready = 1;
    return r;
}
static d2ku_rc snapshot_restore(d2ku_ctx *c, const d2ku_journal *j) {
    int d = snapshot_dir(c, j->transaction_id, 0);
    if (d < 0)
        return D2KU_RECOVERY;
    char hs[65 + 1];
    unsigned char expected[32], actual[32];
    d2ku_rc r = small_read(d, "seal", hs, sizeof hs);
    if (r == D2KU_OK &&
        (!unhex(hs, expected) || snapshot_hash(c, d, actual) != D2KU_OK ||
         memcmp(expected, actual, 32)))
        r = D2KU_RECOVERY;
    d2ku_snapshot_path p[D2KU_SNAPSHOT_PATHS_MAX];
    int present[D2KU_SNAPSHOT_PATHS_MAX];
    size_t n = 0;
    if (r == D2KU_OK)
        r = inventory(d, p, present, &n);
    /* Validate the entire immutable snapshot before touching any live data.
     * Each path then has a restartable copy+rename, never a move out of the
     * backup. */
    for (size_t k = 0; r == D2KU_OK && k < n; k++) {
        int temp = mkdir_sync(c, c->root_dirfd, ".restore-update");
        if (temp < 0) {
            r = D2KU_IO;
            break;
        }
        r = remove_tree(temp, p[k].name);
        if (r == D2KU_OK && present[k]) {
            uint64_t bytes = 0;
            r = tree(c, d, p[k].name, temp, 0, &bytes, NULL);
        }
        if (r == D2KU_OK)
            r = syncfd(c, temp);
        if (r == D2KU_OK)
            r = remove_tree(c->root_dirfd, p[k].name);
        if (r == D2KU_OK && present[k])
            r = rename_file(c, temp, p[k].name, c->root_dirfd, p[k].name);
        if (r == D2KU_OK)
            r = syncfd(c, c->root_dirfd);
        close(temp);
    }
    close(d);
    return r;
}
/* Child groups prevent a timed-out candidate or its descendants keeping a
 * writer alive after recovery acquires the maintenance lock. */
typedef struct {
    pid_t pid;
    int fd;
    uint64_t last;
    int ready;
    char pending[128];
    size_t used;
} child_probe;
static uint64_t real_mono(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static void child_stop(child_probe *p) {
    if (p->pid > 0) {
        kill(-p->pid, SIGKILL);
        kill(p->pid, SIGKILL);
        while (waitpid(p->pid, NULL, 0) < 0 && errno == EINTR) {
        }
        p->pid = 0;
    }
    if (p->fd >= 0) {
        close(p->fd);
        p->fd = -1;
    }
}
static d2ku_rc child_run(d2ku_ctx *c, int dir, const char *binary,
                         const char *option, const char *expected) {
    int pipefd[2], gate[2];
    if (pipe(pipefd))
        return D2KU_IO;
    if (pipe(gate)) {
        close(pipefd[0]);
        close(pipefd[1]);
        return D2KU_IO;
    }
    pid_t parent = getpid(), p = fork();
    if (p < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        close(gate[0]);
        close(gate[1]);
        return D2KU_IO;
    }
    if (!p) {
#ifdef __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
            _exit(126);
#else
        (void)parent;
#endif
        close(gate[1]);
        close(pipefd[0]);
        if (c->boot_control_fd > 2) {
            close(c->boot_control_fd);
            close(3);
        }
        unsigned char release;
        ssize_t n;
        do {
            n = read(gate[0], &release, 1);
        } while (n < 0 && errno == EINTR);
        close(gate[0]);
        if (n != 1 || release != 0xa5)
            _exit(126);

        if (dup2(pipefd[1], STDOUT_FILENO) < 0 || fchdir(dir))
            _exit(126);
        close(pipefd[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            close(null);
        }
        char path[80];
        snprintf(path, sizeof path, "./%s", binary);
        execl(path, binary, option, (char *)NULL);
        _exit(127);
    }
    close(gate[0]);
    close(pipefd[1]);
    d2ku_rc registered = d2ku_boot_group(c, p, 1);
    int grouped =
        registered == D2KU_OK
            ? (c->transaction.process_group
                   ? c->transaction.process_group(c->transaction.arg, p, p)
                   : setpgid(p, p))
            : -1;
    const unsigned char release = 0xa5;
    d2ku_rc released =
        grouped == 0 ? writeall(c, gate[1], &release, 1) : D2KU_IO;
    close(gate[1]);
    if (released != D2KU_OK) {
        kill(p, SIGKILL);
        while (waitpid(p, NULL, 0) < 0 && errno == EINTR) {
        }
        if (registered == D2KU_OK)
            (void)d2ku_boot_group(c, p, 0);
        close(pipefd[0]);
        return D2KU_IO;
    }
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    char b[128];
    size_t n = 0;
    uint64_t deadline = real_mono() + 5000;
    int status = 0, exited = 0;
    d2ku_rc r = D2KU_HEALTH;
    while (real_mono() < deadline) {
        ssize_t z = read(pipefd[0], b + n, sizeof b - 1 - n);
        if (z > 0) {
            n += (size_t)z;
            if (n == sizeof b - 1)
                break;
        } else if (z < 0 && errno != EAGAIN && errno != EINTR)
            break;
        pid_t w = waitpid(p, &status, WNOHANG);
        if (w == p) {
            exited = 1; /* Drain the already closed output pipe. */
            while (n < sizeof b - 1 &&
                   (z = read(pipefd[0], b + n, sizeof b - 1 - n)) > 0)
                n += (size_t)z;
            break;
        }
        if (w < 0)
            break;
        struct pollfd pollfd = {pipefd[0], POLLIN, 0};
        poll(&pollfd, 1, 10);
    }
    b[n] = 0;
    if (exited && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        (!expected || !strcmp(expected, b)))
        r = D2KU_OK;
    kill(-p, SIGKILL);
    if (!exited) {
        kill(p, SIGKILL);
        while (waitpid(p, NULL, 0) < 0 && errno == EINTR) {
        }
    }
    close(pipefd[0]);
    d2ku_rc cleaned = c->boot_control_fd > 2 ? d2ku_boot_group(c, p, 0)
                                             : d2ku_group_cleanup(p);
    return cleaned == D2KU_OK ? r : cleaned;
}
static d2ku_rc offline_check(d2ku_ctx *c, int dir, const char *id) {
    if (c->transaction.offline)
        return c->transaction.offline(c->transaction.arg, dir, id);
    static const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg",
                                 "d2k-update"};
    char expected[68];
    snprintf(expected, sizeof expected, "%s\n", id);
    for (size_t k = 0; k < 5; k++) {
        d2ku_rc r = child_run(c, dir, bins[k], "--release-id", expected);
        if (r != D2KU_OK)
            return r;
        r = child_run(c, dir, bins[k], "--self-check", NULL);
        if (r != D2KU_OK)
            return r;
    }
    return child_run(c, dir, "d2k-update", "--boot-protocol", "1\n");
}
static d2ku_rc probe_start(d2ku_ctx *c, const char *id, child_probe *p) {
    memset(p, 0, sizeof *p);
    p->fd = -1;
    if (c->transaction.updater_probe)
        return c->transaction.updater_probe(c->transaction.arg, "start", id);
    int d = release_dir(c, id), fds[2];
    if (d < 0)
        return D2KU_IO;
    int root = fcntl(c->root_dirfd, F_DUPFD_CLOEXEC, 10);
    if (root < 0) {
        close(d);
        return D2KU_IO;
    }
    if (pipe(fds)) {
        close(d);
        close(root);
        return D2KU_IO;
    }
    pid_t parent = getpid(), pid = fork();
    if (pid < 0) {
        close(root);
        close(d);
        close(fds[0]);
        close(fds[1]);
        return D2KU_IO;
    }
    if (!pid) {
#ifdef __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
            _exit(126);
#else
        (void)parent;
#endif
        setpgid(0, 0);
        if (c->boot_control_fd > 2)
            close(c->boot_control_fd);
        close(fds[0]);
        if (fchdir(d))
            _exit(126);
        close(d);
        if (dup2(fds[1], 3) < 0)
            _exit(126);
        if (fds[1] != 3)
            close(fds[1]);
        if (dup2(root, 4) < 0)
            _exit(126);
        close(root);
        fcntl(3, F_SETFD, 0);
        fcntl(4, F_SETFD, 0);
        fcntl(3, F_SETFL, O_NONBLOCK);
        execl("./d2k-update", "d2k-update", "--boot-probe", "3", "--root-fd",
              "4", (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    close(root);
    close(d);
    close(fds[1]);
    p->pid = pid;
    p->fd = fds[0];
    fcntl(p->fd, F_SETFL, O_NONBLOCK);
    p->last = real_mono();
    return D2KU_OK;
}
static d2ku_rc probe_poll(d2ku_ctx *c, const char *id, child_probe *p) {
    if (c->transaction.updater_probe)
        return c->transaction.updater_probe(c->transaction.arg, "poll", id);
    int w;
    pid_t exited = waitpid(p->pid, &w, WNOHANG);
    if (exited != 0) {
        if (exited == p->pid) {
            kill(-p->pid, SIGKILL);
            p->pid = 0;
        }
        return D2KU_HEALTH;
    }
    for (;;) {
        char ch;
        ssize_t n = read(p->fd, &ch, 1);
        if (n < 0 && (errno == EAGAIN || errno == EINTR))
            break;
        if (n <= 0)
            return D2KU_HEALTH;
        if (p->used == sizeof p->pending - 1)
            return D2KU_HEALTH;
        p->pending[p->used++] = ch;
        if (ch == '\n') {
            p->pending[p->used] = 0;
            if (!strcmp(p->pending, "D2KU1 READY\n"))
                p->ready = 1;
            else if (strcmp(p->pending, "D2KU1 PULSE\n"))
                return D2KU_HEALTH;
            p->used = 0;
            p->last = real_mono();
        }
    }
    if (real_mono() - p->last >= D2KU_HEARTBEAT_MS)
        return D2KU_HEALTH;
    return p->ready ? D2KU_OK : D2KU_BUSY;
}
static void probe_stop(d2ku_ctx *c, const char *id, child_probe *p) {
    if (c->transaction.updater_probe)
        (void)c->transaction.updater_probe(c->transaction.arg, "stop", id);
    else
        child_stop(p);
}
static d2ku_rc validate(d2ku_ctx *c, d2ku_journal *j, d2ku_status *s,
                        int updater, child_probe *keep) {
    child_probe p = {.fd = -1};
    d2ku_rc r = D2KU_OK;
    memset(s, 0, sizeof *s);
    if (updater) {
        r = probe_start(c, j->new_release_id, &p);
        if (r != D2KU_OK)
            return r;
    }
    uint64_t start = real_mono(), observation_start = 0;
    int observing = 0;
    for (;;) {
        d2ku_rc ready =
            updater ? probe_poll(c, j->new_release_id, &p) : D2KU_OK;
        if (ready != D2KU_OK && ready != D2KU_BUSY) {
            r = ready;
            break;
        } /* A pulse-only candidate cannot postpone READY forever. */
        if (ready == D2KU_BUSY && real_mono() - start >= D2KU_HEARTBEAT_MS) {
            r = D2KU_HEALTH;
            break;
        }
        if (ready == D2KU_BUSY) {
            r = wait_ms(c, 1000);
            if (r != D2KU_OK)
                break;
            continue;
        }
        uint64_t stamp;
        if (c->clock.monotonic(c->clock.arg, &stamp) != D2KU_OK) {
            r = D2KU_TIME;
            break;
        }
        if (!observing) {
            observation_start = stamp;
            observing = 1;
        }
        if (stamp < observation_start) {
            r = D2KU_TIME;
            break;
        }
        r = d2ku_health(c, j, s);
        if (r != D2KU_OK)
            break;
        if (s->health_complete && ready == D2KU_OK)
            break;
        if ((stamp - observation_start) / 1000000 >= D2KU_VALIDATION_MS) {
            r = D2KU_HEALTH;
            break;
        }
        r = wait_ms(c, 1000);
        if (r != D2KU_OK)
            break;
    }
    if (updater) {
        if (r == D2KU_OK && keep)
            *keep = p;
        else
            probe_stop(c, j->new_release_id, &p);
    }
    return r;
}
static d2ku_rc failed(d2ku_ctx *c, d2ku_journal *j) {
    j->recovery_reason = D2KU_RECOVERY;
    (void)service(c, "remove-rules", j->old_release_id, j->active_services);
    (void)d2ku_tx_phase(c, j, D2KU_RECOVERY_FAILED);
    return D2KU_RECOVERY;
}
static d2ku_rc quarantine(d2ku_ctx *c, const d2ku_journal *j) {
    d2ku_persistent_state p;
    d2ku_rc rc = d2ku_persistent_load(c, &p);
    if (rc != D2KU_OK)
        return rc;
    p.sequence++;
    p.policy.has_quarantined_release = 1;
    p.policy.quarantine_reason =
        j->failure_reason == D2KU_OK ? D2KU_RECOVERY : j->failure_reason;
    memcpy(p.policy.quarantined_release_sha256, j->new_manifest_sha256, 32);
    return d2ku_persistent_store(c, &p);
}
d2ku_rc d2ku_tx_recover_locked(d2ku_ctx *c, d2ku_status *s) {
    d2ku_journal j;
    d2ku_rc r = d2ku_journal_load(c, &j);
    if (r == D2KU_ABSENT)
        return D2KU_OK;
    if (r != D2KU_OK)
        return r;
    if (j.phase == D2KU_RECOVERY_FAILED)
        return D2KU_RECOVERY;
    char active[D2KU_ID_MAX + 1];
    unsigned char h[32];
    if (d2ku_tx_current(c, active) != D2KU_OK)
        return failed(c, &j);
    if (j.phase == D2KU_COMMITTED || j.phase == D2KU_ROLLED_BACK) {
        const char *want =
            j.phase == D2KU_COMMITTED ? j.new_release_id : j.old_release_id;
        const unsigned char *hash = j.phase == D2KU_COMMITTED
                                        ? j.new_manifest_sha256
                                        : j.old_manifest_sha256;
        if (strcmp(active, want) || d2ku_tx_receipt(c, want, h) != D2KU_OK ||
            memcmp(h, hash, 32))
          return failed(c, &j);
        /* Reconcile visible terminal record against current; boot service start
         * is separately adapter-owned. Never restore a stale snapshot after
         * commit. The visible generation may predate its directory fsync.
         * Exact-generation retry re-syncs that inode and its parent before
         * recovery accepts it as durable; no new generation is invented. */
        return d2ku_journal_store(c, &j);
    }
    if (d2ku_tx_receipt(c, j.old_release_id, h) != D2KU_OK ||
        memcmp(h, j.old_manifest_sha256, 32))
      return failed(c, &j);
    if (j.phase < D2KU_STOPPING) {
        if (strcmp(active, j.old_release_id))
            return failed(c, &j);
        return d2ku_tx_phase(c, &j, D2KU_ROLLED_BACK);
    }
    if (strcmp(active, j.old_release_id) && strcmp(active, j.new_release_id))
        return failed(c, &j);
    if (j.failure_reason == D2KU_OK)
        j.failure_reason = D2KU_RECOVERY;
    if (d2ku_tx_phase(c, &j, D2KU_ROLLING_BACK) != D2KU_OK)
        return failed(c, &j);
    if (service(c, "stop", active, j.active_services) != D2KU_OK)
        return failed(c, &j);
    if (strcmp(active, j.old_release_id) &&
        service(c, "stop", j.old_release_id, j.active_services) != D2KU_OK)
        return failed(c, &j);
    if (j.snapshot_ready && snapshot_restore(c, &j) != D2KU_OK)
        return failed(c, &j);
    if (switch_current(c, j.old_release_id) != D2KU_OK ||
        service(c, "start", j.old_release_id, j.active_services) != D2KU_OK)
        return failed(c, &j);
    d2ku_journal check = j;
    check.phase = D2KU_VALIDATING;
    strcpy(check.new_release_id, j.old_release_id);
    check.new_release_id_len = j.old_release_id_len;
    memcpy(check.new_manifest_sha256, j.old_manifest_sha256, 32);
    /* Recover across boot IDs using the platform's current monotonic identity.
     */
    d2ku_clock_sample now;
    if (c->clock.snapshot && c->clock.snapshot(c->clock.arg, &now) == D2KU_OK) {
        strcpy(check.progress_boot_id, now.boot_id);
        check.progress_boot_id_len = strlen(now.boot_id);
    }
    if (validate(c, &check, s, 0, NULL) != D2KU_OK)
        return failed(c, &j);
    if (quarantine(c, &j) != D2KU_OK)
        return failed(c, &j);
    if (d2ku_tx_phase(c, &j, D2KU_ROLLED_BACK) != D2KU_OK)
        return failed(c, &j);
    return D2KU_OK;
}
static int terminal(d2ku_phase p) {
    return p == D2KU_COMMITTED || p == D2KU_ROLLED_BACK;
}
static d2ku_rc duplicate(d2ku_ctx *c, const d2ku_request *r,
                         d2ku_command_op command, int *found) {
  d2ku_journal j;
  *found = 0;
  d2ku_rc rc = d2ku_journal_load(c, &j);
  if (rc == D2KU_ABSENT)
    return D2KU_OK;
  if (rc != D2KU_OK)
    return rc;
  if (!strcmp(r->transaction_id, j.transaction_id)) {
    *found = 1;
    if (j.command != command || strcmp(r->release_id, j.new_release_id) ||
        memcmp(r->manifest_sha256, j.new_manifest_sha256, 32))
      return D2KU_INVALID;
    return j.phase == D2KU_COMMITTED         ? D2KU_OK
           : j.phase == D2KU_ROLLED_BACK     ? D2KU_HEALTH
           : j.phase == D2KU_RECOVERY_FAILED ? D2KU_RECOVERY
                                             : D2KU_BUSY;
  }
  return terminal(j.phase)                 ? D2KU_OK
         : j.phase == D2KU_RECOVERY_FAILED ? D2KU_RECOVERY
                                           : D2KU_BUSY;
}
static d2ku_rc bind_current(d2ku_ctx *c, const d2ku_request *r) {
    char id[D2KU_ID_MAX + 1];
    unsigned char h[32];
    d2ku_rc rc = d2ku_tx_current(c, id);
    if (rc != D2KU_OK)
        return rc;
    if (strcmp(id, r->expected_release_id))
        return D2KU_BUSY;
    rc = d2ku_tx_receipt(c, id, h);
    if (rc != D2KU_OK)
        return rc;
    return memcmp(h, r->expected_manifest_sha256, 32) ? D2KU_BUSY : D2KU_OK;
}
static d2ku_rc request_valid(d2ku_ctx *c, const d2ku_request *r, int rollback) {
    if (!c || !r || !valid_id(r->transaction_id) ||
        !valid_id(r->expected_release_id) || !valid_id(r->release_id) ||
        !strcmp(r->expected_release_id, r->release_id) ||
        !c->transaction.capture || !c->transaction.services ||
        !c->clock.monotonic)
        return D2KU_INVALID;
    d2ku_rc rc = paths_valid(c);
    if (rc != D2KU_OK)
        return rc;
    if (rollback)
        return D2KU_OK;
    const d2ku_manifest *m = r->manifest;
    const d2ku_index *i = r->index;
    if (!m || !i || r->archive_fd < 0 || m->schema != 1 || i->schema != 1 ||
        strcmp(m->release_id, r->release_id) ||
        strcmp(i->release_id, r->release_id) ||
        memcmp(m->document_sha256, r->manifest_sha256, 32) ||
        memcmp(i->manifest_sha256, r->manifest_sha256, 32) ||
        !c->has_accepted_index || i->sequence != c->accepted_sequence ||
        memcmp(i->document_sha256, c->accepted_index_sha256, 32))
        return D2KU_INVALID;
    if (m->wire != c->wire_version || m->state != c->state_version ||
        m->min_updater > c->updater_version || c->updater_version != 1)
        return D2KU_INCOMPATIBLE;
    d2ku_clock_sample now;
    rc = d2ku_read_clock(&c->clock, &now);
    if (rc != D2KU_OK)
        return rc;
    if (now.utc_seconds >= i->expires_at || i->issued_at > now.utc_seconds)
        return D2KU_EXPIRED;
    return D2KU_OK;
}
static d2ku_rc verify_release_files(d2ku_ctx *c, int dir,
                                    const d2ku_manifest *m) {
    if (m->package_count > D2KU_PACKAGES_MAX || m->file_count > D2KU_FILES_MAX)
        return D2KU_INVALID;
    const d2ku_package *pkg = NULL;
    for (size_t k = 0; k < m->package_count; k++)
        if (!strcmp(m->packages[k].abi, c->abi))
            pkg = &m->packages[k];
    if (!pkg || !pkg->file_count || pkg->file_offset > m->file_count ||
        pkg->file_count > m->file_count - pkg->file_offset)
        return D2KU_INVALID;
    for (size_t k = pkg->file_offset; k < pkg->file_offset + pkg->file_count;
         k++) {
        const d2ku_file *file = &m->files[k];
        if (!file->path_len || file->path_len > D2KU_PATH_MAX ||
            strnlen(file->path, sizeof file->path) != file->path_len)
            return D2KU_INVALID;
        char path[D2KU_PATH_MAX + 1];
        strcpy(path, file->path);
        int at = dup(dir), fd = -1;
        char *save = NULL, *part = strtok_r(path, "/", &save);
        if (at < 0)
            return D2KU_IO;
        while (part) {
            char *next = strtok_r(NULL, "/", &save);
            if (!strcmp(part, ".") || !strcmp(part, "..")) {
                close(at);
                return D2KU_INVALID;
            }
            if (next) {
                int sub = directory(at, part);
                close(at);
                at = sub;
                if (at < 0)
                    return D2KU_UNTRUSTED;
            } else
                fd = openat(at, part,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            part = next;
        }
        close(at);
        if (fd < 0)
            return D2KU_UNTRUSTED;
        struct stat st;
        d2ku_rc rc = D2KU_UNTRUSTED;
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if (!md) {
            close(fd);
            return D2KU_IO;
        }
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
            st.st_size < 0 || (uint64_t)st.st_size != file->size ||
            (st.st_mode & 0777) != file->mode ||
            EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1)
            goto file_done;
        char buf[16384];
        uint64_t total = 0;
        for (;;) {
            ssize_t n = read(fd, buf, sizeof buf);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0)
                goto file_done;
            if (!n)
                break;
            total += (uint64_t)n;
            if (EVP_DigestUpdate(md, buf, (size_t)n) != 1)
                goto file_done;
        }
        unsigned char h[32];
        unsigned len;
        if (total == file->size && EVP_DigestFinal_ex(md, h, &len) == 1 &&
            len == 32 && !memcmp(h, file->sha256, 32))
            rc = D2KU_OK;
    file_done:
        EVP_MD_CTX_free(md);
        close(fd);
        if (rc != D2KU_OK)
            return rc;
    }
    return D2KU_OK;
}
static d2ku_rc prepare(d2ku_ctx *c, const d2ku_request *r) {
    int all = directory(c->root_dirfd, "releases");
    if (all < 0)
        return D2KU_IO;
    struct stat root_stat, release_stat;
    if (fstat(c->root_dirfd, &root_stat) || fstat(all, &release_stat) ||
        root_stat.st_dev != release_stat.st_dev) {
        close(all);
        return D2KU_INCOMPATIBLE;
    }
    struct stat st;
    if (!fstatat(all, r->release_id, &st, AT_SYMLINK_NOFOLLOW)) {
        unsigned char h[32];
        close(all);
        d2ku_rc rc = d2ku_tx_receipt(
            c, r->release_id,
            h); /* Existing immutable ID may be reused only with same
                 * receipt. Offline checks are repeated; package payload
                 * never overwrites an existing release. */
        if (rc != D2KU_OK || memcmp(h, r->manifest_sha256, 32))
            return D2KU_INVALID;
        int d = release_dir(c, r->release_id);
        if (d < 0)
            return D2KU_IO;
        rc = verify_release_files(c, d, r->manifest);
        if (rc == D2KU_OK)
            rc = offline_check(c, d, r->release_id);
        close(d);
        return rc;
    }
    if (errno != ENOENT) {
        close(all);
        return D2KU_IO;
    }
    char temp[96];
    snprintf(temp, sizeof temp, ".stage-%s", r->transaction_id);
    if (mkdirat(all, temp, 0700)) {
        close(all);
        return D2KU_IO;
    }
    int d = directory(all, temp);
    if (d < 0) {
        close(all);
        return D2KU_IO;
    }
    d2ku_rc rc = syncfd(c, all);
    d2ku_ctx stage = *c;
    stage.staging_dirfd = d;
    if (rc == D2KU_OK)
        rc = d2ku_stage(&stage, r->manifest, r->archive_fd);
    if (rc == D2KU_OK)
        rc = verify_release_files(c, d, r->manifest);
    if (rc == D2KU_OK)
        rc = offline_check(c, d, r->release_id);
    if (rc == D2KU_OK)
        rc = receipt_write(c, d, r->manifest_sha256);
    if (rc == D2KU_OK)
        rc = rename_file(c, all, temp, all, r->release_id);
    if (rc == D2KU_OK)
        rc = syncfd(c, all);
    close(d);
    if (rc != D2KU_OK)
        (void)remove_tree(all, temp);
    close(all);
    return rc;
}
static d2ku_rc execute(d2ku_ctx *c, const d2ku_request *r, d2ku_status *s,
                       int rollback) {
    d2ku_rc rc;
    child_probe running = {.fd = -1};
    int probe_held = 0;
    int lock = -1, found = 0;
    rc = d2ku_maintenance_lock(c, &lock);
    if (rc != D2KU_OK)
        return rc;
    c->maintenance_lock_fd = lock;
    if (c->refresh && (rc = c->refresh(c->refresh_arg)) != D2KU_OK)
      goto out;
    rc = duplicate(c, r, rollback ? D2KU_CMD_ROLLBACK : D2KU_CMD_INSTALL,
                   &found);
    if (rc != D2KU_OK || found)
        goto out;
    rc = request_valid(c, r, rollback);
    if (rc != D2KU_OK)
        goto out;
    rc = bind_current(c, r);
    if (rc != D2KU_OK)
        goto out;
    rc = space(c, NULL); /* prepared release is already allocated */
    if (rc != D2KU_OK)
        goto out;
    if (rollback) {
        d2ku_journal prev;
        unsigned char h[32];
        rc = d2ku_journal_load(c, &prev);
        if (rc != D2KU_OK || prev.phase != D2KU_COMMITTED ||
            strcmp(prev.old_release_id, r->release_id) ||
            memcmp(prev.old_manifest_sha256, r->manifest_sha256, 32)) {
            rc = D2KU_INVALID;
            goto out;
        }
        rc = d2ku_tx_receipt(c, r->release_id, h);
        if (rc != D2KU_OK || memcmp(h, r->manifest_sha256, 32)) {
            rc = D2KU_INCOMPATIBLE;
            goto out;
        }
    }
    if (r->automatic) {
      rc = d2ku_auto_reservation_valid(c, r);
      if (rc != D2KU_OK)
        goto out;
    }
    d2ku_journal j = {0};
    j.schema = 1;
    j.command = rollback ? D2KU_CMD_ROLLBACK : D2KU_CMD_INSTALL;
    strcpy(j.transaction_id, r->transaction_id);
    j.transaction_id_len = strlen(r->transaction_id);
    strcpy(j.old_release_id, r->expected_release_id);
    j.old_release_id_len = strlen(r->expected_release_id);
    strcpy(j.new_release_id, r->release_id);
    j.new_release_id_len = strlen(r->release_id);
    memcpy(j.old_manifest_sha256, r->expected_manifest_sha256, 32);
    memcpy(j.new_manifest_sha256, r->manifest_sha256, 32);
    d2ku_clock_sample now;
    rc = d2ku_read_clock(&c->clock, &now);
    if (rc != D2KU_OK)
        goto out;
    strcpy(j.progress_boot_id, now.boot_id);
    j.progress_boot_id_len = strlen(now.boot_id);
    j.progress_utc = now.utc_seconds;
    rc = c->transaction.capture(c->transaction.arg, &j.active_services);
    if (rc != D2KU_OK)
        goto out;
    if (j.active_services & ~UINT64_C(15)) {
        rc = D2KU_INVALID;
        goto out;
    }
    rc = snapshot_begin(c, &j);
    if (rc != D2KU_OK)
        goto out;
    rc = d2ku_tx_phase(c, &j, D2KU_PREPARED);
    if (rc != D2KU_OK)
        goto out;
    rc = d2ku_tx_phase(c, &j, D2KU_STOPPING);
    if (rc != D2KU_OK)
        goto recover;
    rc = service(c, "stop", j.old_release_id, j.active_services);
    if (rc != D2KU_OK)
        goto recover;
    rc = snapshot_finish(c, &j);
    if (rc != D2KU_OK)
        goto recover;
    rc = d2ku_tx_phase(c, &j, D2KU_SWITCHING);
    if (rc != D2KU_OK)
        goto recover;
    rc = switch_current(c, j.new_release_id);
    if (rc != D2KU_OK)
        goto recover;
    rc = d2ku_tx_phase(c, &j, D2KU_STARTING);
    if (rc != D2KU_OK)
        goto recover;
    rc = service(c, "start", j.new_release_id, j.active_services);
    if (rc != D2KU_OK)
        goto recover;
    rc = d2ku_tx_phase(c, &j, D2KU_VALIDATING);
    if (rc != D2KU_OK)
        goto recover;
    rc = validate(c, &j, s, 1, &running);
    if (rc != D2KU_OK)
        goto recover;
    probe_held = 1;
    rc = probe_poll(c, j.new_release_id, &running);
    if (rc != D2KU_OK)
        goto recover;
    rc = d2ku_tx_phase(c, &j, D2KU_COMMITTED);
    if (rc == D2KU_OK)
        goto out;
    /* A failed terminal directory fsync may leave COMMITTED visible. Force an
     * explicit rollback intent using the actual latest sequence before
     * recovery; never interpret the failed store as proof that the old slot is
     * newest. */
recover:
    {
        d2ku_rc original = rc;
        j.failure_reason = original;
        if (probe_held) {
            probe_stop(c, r->release_id, &running);
            probe_held = 0;
        }
        if (d2ku_tx_phase(c, &j, D2KU_ROLLING_BACK) != D2KU_OK) {
            rc = failed(c, &j);
            goto out;
        }
        rc = d2ku_tx_recover_locked(c, s);
        if (rc == D2KU_OK)
            rc = original;
    }
out:
    if (probe_held)
        probe_stop(c, r->release_id, &running);
    c->maintenance_lock_fd = -1;
    d2ku_maintenance_unlock(lock);
    return rc;
}
d2ku_rc d2ku_install(d2ku_ctx *c, const d2ku_request *r, d2ku_status *s) {
    if (!c || !r || !s)
        return D2KU_INVALID;
    int found = 0;
    d2ku_rc rc = duplicate(c, r, D2KU_CMD_INSTALL, &found);
    if (rc != D2KU_OK || found)
        return rc;
    rc = request_valid(c, r, 0);
    if (rc != D2KU_OK)
        return rc;
    int allocated = release_dir(c, r->release_id);
    if (allocated >= 0)
        close(allocated);
    rc = space(c, allocated >= 0 ? NULL : r->manifest);
    if (rc != D2KU_OK)
        return rc; /* Package preparation takes place before stopping or holding
                      maintenance. */
    rc = prepare(c, r);
    if (rc != D2KU_OK)
        return rc;
    return execute(c, r, s, 0);
}
d2ku_rc d2ku_rollback(d2ku_ctx *c, const d2ku_request *r, d2ku_status *s) {
    if (!c || !r || !s)
        return D2KU_INVALID;
    d2ku_rc rc = request_valid(c, r, 1);
    if (rc != D2KU_OK)
        return rc;
    return execute(c, r, s, 1);
}
