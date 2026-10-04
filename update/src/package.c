#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "d2k_update.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Never enter active/root/config: every filesystem write uses staging dirfds. */
typedef struct {
    char name[D2KU_PATH_MAX + 1];
    int explicit_entry;
} directory;
static int safe_path(const char *p, size_t len) {
    if (!len || len > D2KU_PATH_MAX || p[len] || strlen(p) != len)
        return 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || p[i] == '/') {
            size_t n = i - start;
            if (!n || (n == 1 && p[start] == '.') ||
                (n == 2 && p[start] == '.' && p[start + 1] == '.'))
                return 0;
            start = i + 1;
        } else if (!((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z') ||
                     (p[i] >= '0' && p[i] <= '9') || p[i] == '.' || p[i] == '_' || p[i] == '-'))
            return 0;
    }
    return 1;
}
static int read_at(int fd, void *out, size_t n, uint64_t off) {
    if (off > INT64_MAX || n > (uint64_t)INT64_MAX - off)
        return 0;
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, (char *)out + got, n - got, (off_t)(off + got));
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return 0;
        got += (size_t)r;
    }
    return 1;
}
static int zeros(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return 0;
    return 1;
}
static int octal(const unsigned char *p, size_t n, uint64_t *out) {
    size_t i = 0;
    uint64_t v = 0;
    int digits = 0;
    while (i < n && p[i] == ' ')
        i++;
    while (i < n && p[i] >= '0' && p[i] <= '7') {
        if (v > (UINT64_MAX - 7) / 8)
            return 0;
        v = v * 8 + p[i++] - '0';
        digits = 1;
    }
    while (i < n && (p[i] == 0 || p[i] == ' '))
        i++;
    if (!digits || i != n)
        return 0;
    *out = v;
    return 1;
}
static d2ku_rc sync_one(d2ku_ctx *ctx, int fd) {
    if (ctx->sync_fd)
        return ctx->sync_fd(ctx->io_arg, fd);
    return fsync(fd) == 0 ? D2KU_OK : D2KU_IO;
}
static int parent_fd(int base, const char *path, char leaf[D2KU_PATH_MAX + 1]) {
    char copy[D2KU_PATH_MAX + 1];
    strcpy(copy, path);
    int fd = dup(base);
    if (fd < 0)
        return -1;
    char *start = copy, *slash;
    while ((slash = strchr(start, '/'))) {
        *slash = 0;
        int next = openat(fd, start, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(fd);
        if (next < 0)
            return -1;
        fd = next;
        start = slash + 1;
    }
    strcpy(leaf, start);
    return fd;
}
static d2ku_rc whole_hash(int fd, uint64_t size, const unsigned char expected[32]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char buffer[65536], hash[32];
    unsigned int n = 0;
    if (!md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(md);
        return D2KU_IO;
    }
    d2ku_rc rc = D2KU_OK;
    for (uint64_t off = 0; off < size;) {
        size_t take = size - off < sizeof(buffer) ? (size_t)(size - off) : sizeof(buffer);
        if (!read_at(fd, buffer, take, off)) {
            rc = D2KU_IO;
            break;
        }
        if (EVP_DigestUpdate(md, buffer, take) != 1) {
            rc = D2KU_IO;
            break;
        }
        off += take;
    }
    if (rc == D2KU_OK && (EVP_DigestFinal_ex(md, hash, &n) != 1 || n != 32))
        rc = D2KU_IO;
    if (rc == D2KU_OK && CRYPTO_memcmp(hash, expected, 32))
        rc = D2KU_UNTRUSTED;
    EVP_MD_CTX_free(md);
    return rc;
}
static int empty_dir(int fd) {
    /* openat gives an independent directory offset; dup would share readdir's. */
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scan < 0)
        return 0;
    DIR *dir = fdopendir(scan);
    if (!dir) {
        close(scan);
        return 0;
    }
    struct dirent *e;
    int empty = 1;
    errno = 0;
    while ((e = readdir(dir)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            empty = 0;
            break;
        }
    if (errno)
        empty = 0;
    closedir(dir);
    return empty;
}
d2ku_rc d2ku_stage(d2ku_ctx *ctx, const d2ku_manifest *m, int archive_fd) {
    if (!ctx || !m || m->schema != 1 || !m->package_count || m->package_count > D2KU_PACKAGES_MAX ||
        !m->file_count || m->file_count > D2KU_FILES_MAX)
        return D2KU_INVALID;
    if (m->min_updater > ctx->updater_version || m->wire != ctx->wire_version ||
        m->state != ctx->state_version)
        return D2KU_INCOMPATIBLE;
    const d2ku_package *pkg = NULL;
    if (strnlen(ctx->abi, sizeof(ctx->abi)) >= sizeof(ctx->abi))
        return D2KU_INVALID;
    for (size_t i = 0; i < m->package_count; i++) {
        const d2ku_package *p = &m->packages[i];
        if (!p->abi_len || p->abi_len > D2KU_ABI_MAX || p->abi[p->abi_len])
            return D2KU_INVALID;
        if (!strcmp(p->abi, ctx->abi)) {
            if (pkg)
                return D2KU_INVALID;
            pkg = p;
        }
    }
    if (!pkg)
        return D2KU_INCOMPATIBLE;
    if (!pkg->file_count || pkg->file_offset > m->file_count ||
        pkg->file_count > m->file_count - pkg->file_offset || pkg->size < 1024 || pkg->size % 512 ||
        pkg->size > INT64_MAX)
        return D2KU_INVALID;
    const d2ku_file *files = m->files + pkg->file_offset;
    uint64_t payload = 0;
    size_t dir_cap = 0;
    for (size_t i = 0; i < pkg->file_count; i++) {
        if (!safe_path(files[i].path, files[i].path_len) ||
            (files[i].mode != 0644 && files[i].mode != 0755) || files[i].size > pkg->size - payload)
            return D2KU_INVALID;
        payload += files[i].size;
        for (size_t j = 0; j < files[i].path_len; j++)
            if (files[i].path[j] == '/')
                dir_cap++;
        for (size_t j = 0; j < i; j++) {
            size_t a = files[i].path_len, b = files[j].path_len;
            if (!strcmp(files[i].path, files[j].path) ||
                (a > b && !memcmp(files[i].path, files[j].path, b) && files[i].path[b] == '/') ||
                (b > a && !memcmp(files[j].path, files[i].path, a) && files[j].path[a] == '/'))
                return D2KU_INVALID;
        }
    }
    struct stat st, dst;
    if (fstat(archive_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size != pkg->size)
        return D2KU_INVALID;
    if (fstat(ctx->staging_dirfd, &dst) || !S_ISDIR(dst.st_mode) || (dst.st_mode & 0077) ||
        dst.st_uid != geteuid() || !empty_dir(ctx->staging_dirfd))
        return D2KU_INVALID;
    if (ctx->root_dirfd >= 0) {
        struct stat active;
        if (!fstat(ctx->root_dirfd, &active) && active.st_dev == dst.st_dev &&
            active.st_ino == dst.st_ino)
            return D2KU_INVALID;
    }
    d2ku_rc rc = whole_hash(archive_fd, pkg->size, pkg->sha256);
    if (rc != D2KU_OK)
        return rc;
    directory *dirs = calloc(dir_cap ? dir_cap : 1, sizeof(*dirs));
    unsigned char seen[D2KU_FILES_MAX] = {0}, created[D2KU_FILES_MAX] = {0};
    if (!dirs)
        return D2KU_IO;
    size_t dir_count = 0, dirs_created = 0;
    /* Construct only directories implied by the signed file list, parent first. */
    for (size_t i = 0; i < pkg->file_count; i++)
        for (size_t j = 0; j < files[i].path_len; j++)
            if (files[i].path[j] == '/') {
                char name[D2KU_PATH_MAX + 1];
                memcpy(name, files[i].path, j);
                name[j] = 0;
                size_t k;
                for (k = 0; k < dir_count; k++)
                    if (!strcmp(name, dirs[k].name))
                        break;
                if (k == dir_count)
                    strcpy(dirs[dir_count++].name, name);
            }
    for (size_t i = 0; i < dir_count; i++) {
        char leaf[D2KU_PATH_MAX + 1];
        int parent = parent_fd(ctx->staging_dirfd, dirs[i].name, leaf);
        if (parent < 0) {
            rc = D2KU_IO;
            goto done;
        }
        int result = mkdirat(parent, leaf, 0700);
        close(parent);
        if (result) {
            rc = D2KU_IO;
            goto done;
        }
        dirs_created++;
    }
    uint64_t off = 0;
    unsigned zero_blocks = 0;
    int finished = 0;
    while (off < pkg->size) {
        unsigned char h[512];
        if (!read_at(archive_fd, h, 512, off)) {
            rc = D2KU_IO;
            goto done;
        }
        off += 512;
        if (zeros(h, 512)) {
            zero_blocks++;
            finished = 1;
            continue;
        }
        if (finished) {
            rc = D2KU_INVALID;
            goto done;
        }
        uint64_t stored, sum = 0, mode, size, uid, gid, mtime, major, minor;
        for (size_t i = 0; i < 512; i++)
            sum += i >= 148 && i < 156 ? ' ' : h[i];
        if (memcmp(h + 257, "ustar\00000", 8) || !octal(h + 148, 8, &stored) || stored != sum ||
            !octal(h + 100, 8, &mode) || !octal(h + 124, 12, &size) || !octal(h + 108, 8, &uid) ||
            !octal(h + 116, 8, &gid) || !octal(h + 136, 12, &mtime) || !zeros(h + 157, 100) ||
            !zeros(h + 500, 12)) {
            rc = D2KU_INVALID;
            goto done;
        }
        /* Device fields may be all NUL (canonical regular files) or octal zero. */
        if ((!zeros(h + 329, 8) && (!octal(h + 329, 8, &major) || major)) ||
            (!zeros(h + 337, 8) && (!octal(h + 337, 8, &minor) || minor))) {
            rc = D2KU_INVALID;
            goto done;
        }
        size_t nl = strnlen((char *)h, 100), pl = strnlen((char *)h + 345, 155);
        char name[D2KU_PATH_MAX + 1];
        if (!nl || nl + (pl ? pl + 1 : 0) > D2KU_PATH_MAX) {
            rc = D2KU_INVALID;
            goto done;
        }
        size_t len = 0;
        if (pl) {
            memcpy(name, h + 345, pl);
            len = pl;
            name[len++] = '/';
        }
        memcpy(name + len, h, nl);
        len += nl;
        name[len] = 0;
        char type = (char)h[156];
        if (type == '5' && len && name[len - 1] == '/')
            name[--len] = 0;
        if (!safe_path(name, len)) {
            rc = D2KU_INVALID;
            goto done;
        }
        if (type == '5') {
            if (size || (mode != 0755 && mode != 0700)) {
                rc = D2KU_INVALID;
                goto done;
            }
            size_t i;
            for (i = 0; i < dir_count; i++)
                if (!strcmp(name, dirs[i].name))
                    break;
            if (i == dir_count || dirs[i].explicit_entry) {
                rc = D2KU_INVALID;
                goto done;
            }
            dirs[i].explicit_entry = 1;
            continue;
        }
        if (type != '0' && type != 0) {
            rc = D2KU_INVALID;
            goto done;
        }
        size_t i;
        for (i = 0; i < pkg->file_count; i++)
            if (!strcmp(name, files[i].path))
                break;
        if (i == pkg->file_count || seen[i] || size != files[i].size || mode != files[i].mode ||
            size > pkg->size - off) {
            rc = D2KU_INVALID;
            goto done;
        }
        seen[i] = 1;
        char leaf[D2KU_PATH_MAX + 1];
        int parent = parent_fd(ctx->staging_dirfd, name, leaf);
        if (parent < 0) {
            rc = D2KU_IO;
            goto done;
        }
        int fd = openat(parent, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        close(parent);
        if (fd < 0) {
            rc = D2KU_IO;
            goto done;
        }
        created[i] = 1;
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        unsigned char buf[65536], digest[32];
        unsigned int hn = 0;
        if (!md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(md);
            close(fd);
            rc = D2KU_IO;
            goto done;
        }
        for (uint64_t n = 0; n < size;) {
            size_t take = size - n < sizeof(buf) ? (size_t)(size - n) : sizeof(buf);
            if (!read_at(archive_fd, buf, take, off + n) || EVP_DigestUpdate(md, buf, take) != 1) {
                rc = D2KU_IO;
                break;
            }
            size_t wrote = 0;
            while (wrote < take) {
                ssize_t w = write(fd, buf + wrote, take - wrote);
                if (w < 0 && errno == EINTR)
                    continue;
                if (w <= 0) {
                    rc = D2KU_IO;
                    break;
                }
                wrote += (size_t)w;
            }
            if (rc != D2KU_OK)
                break;
            n += take;
        }
        if (rc == D2KU_OK && (EVP_DigestFinal_ex(md, digest, &hn) != 1 || hn != 32))
            rc = D2KU_IO;
        EVP_MD_CTX_free(md);
        if (rc == D2KU_OK && CRYPTO_memcmp(digest, files[i].sha256, 32))
            rc = D2KU_UNTRUSTED;
        if (rc == D2KU_OK && fchmod(fd, (mode_t)files[i].mode))
            rc = D2KU_IO;
        if (rc == D2KU_OK)
            rc = sync_one(ctx, fd);
        if (close(fd) && rc == D2KU_OK)
            rc = D2KU_IO;
        if (rc != D2KU_OK)
            goto done;
        off += size;
        size_t pad = (size_t)((512 - size % 512) % 512);
        if (pad > pkg->size - off || !read_at(archive_fd, buf, pad, off) || !zeros(buf, pad)) {
            rc = D2KU_INVALID;
            goto done;
        }
        off += pad;
    }
    if (zero_blocks < 2) {
        rc = D2KU_INVALID;
        goto done;
    }
    for (size_t i = 0; i < pkg->file_count; i++)
        if (!seen[i]) {
            rc = D2KU_INVALID;
            goto done;
        }
    /* Bind bytes again after extraction; mutable archive descriptors cannot
     * change content between initial hash and reads into a successful stage. */
    rc = whole_hash(archive_fd, pkg->size, pkg->sha256);
    if (rc != D2KU_OK)
        goto done;
    if (fstat(archive_fd, &st) || st.st_size < 0 || (uint64_t)st.st_size != pkg->size) {
        rc = D2KU_INVALID;
        goto done;
    }
    for (size_t i = dir_count; i > 0; i--) {
        char leaf[D2KU_PATH_MAX + 1];
        int parent = parent_fd(ctx->staging_dirfd, dirs[i - 1].name, leaf);
        int fd =
            parent < 0 ? -1 : openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent >= 0)
            close(parent);
        if (fd < 0) {
            rc = D2KU_IO;
            goto done;
        }
        if (fchmod(fd, 0755))
            rc = D2KU_IO;
        else
            rc = sync_one(ctx, fd);
        if (close(fd) && rc == D2KU_OK)
            rc = D2KU_IO;
        if (rc != D2KU_OK)
            goto done;
    }
    rc = sync_one(ctx, ctx->staging_dirfd);
done:
    if (rc != D2KU_OK) {
        /* Remove only names created by this attempt; pre-existing entries were
         * rejected before writing, and are never removed on that rejection. */
        for (size_t i = 0; i < pkg->file_count; i++)
            if (created[i]) {
                char leaf[D2KU_PATH_MAX + 1];
                int p = parent_fd(ctx->staging_dirfd, files[i].path, leaf);
                if (p >= 0) {
                    if (unlinkat(p, leaf, 0) && errno != ENOENT)
                        rc = D2KU_IO;
                    close(p);
                }
            }
        for (size_t i = dirs_created; i > 0; i--) {
            char leaf[D2KU_PATH_MAX + 1];
            int p = parent_fd(ctx->staging_dirfd, dirs[i - 1].name, leaf);
            if (p >= 0) {
                if (unlinkat(p, leaf, AT_REMOVEDIR) && errno != ENOENT)
                    rc = D2KU_IO;
                close(p);
            }
        }
        /* No prepared state exists on failure; transaction layer owns durable
         * removal of the private staging container after a failed fsync. */
    }
    free(dirs);
    return rc;
}
