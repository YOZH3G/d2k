#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "d2k_update.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned char tar[8192];
static size_t tar_len;
static char root[] = "/tmp/d2ku-package-XXXXXX";
static d2ku_ctx ctx;
static d2ku_manifest m;
static void hash(const void *p, size_t n, unsigned char out[32]) {
    unsigned int len = 0;
    assert(EVP_Digest(p, n, out, &len, EVP_sha256(), NULL) == 1 && len == 32);
}
static void checksum(unsigned char *h) {
    unsigned int sum = 0;
    memset(h + 148, ' ', 8);
    for (size_t i = 0; i < 512; i++)
        sum += h[i];
    snprintf((char *)h + 148, 7, "%06o", sum);
    h[155] = ' ';
}
static void entry(const char *name, char type, const char *body, size_t n, unsigned int mode) {
    unsigned char *h = tar + tar_len;
    assert(tar_len + 1024 < sizeof(tar));
    memset(h, 0, 512);
    assert(strlen(name) < 100);
    strcpy((char *)h, name);
    snprintf((char *)h + 100, 8, "%07o", mode);
    snprintf((char *)h + 108, 8, "%07o", 0);
    snprintf((char *)h + 116, 8, "%07o", 0);
    snprintf((char *)h + 124, 12, "%011llo", (unsigned long long)n);
    snprintf((char *)h + 136, 12, "%011o", 0);
    h[156] = (unsigned char)type;
    memcpy(h + 257, "ustar\00000", 8);
    checksum(h);
    tar_len += 512;
    if (n) {
        memcpy(tar + tar_len, body, n);
        tar_len += (n + 511) / 512 * 512;
    }
}
static void fixture(void) {
    memset(&m, 0, sizeof(m));
    memset(tar, 0, sizeof(tar));
    tar_len = 0;
    m.schema = 1;
    m.min_updater = m.wire = m.state = 1;
    strcpy(m.release_id, "r2");
    m.release_id_len = 2;
    m.package_count = m.file_count = 1;
    strcpy(m.packages[0].abi, "arm64");
    m.packages[0].abi_len = 5;
    m.packages[0].file_count = 1;
    strcpy(m.files[0].path, "bin/d2kc");
    m.files[0].path_len = 8;
    m.files[0].size = 3;
    m.files[0].mode = 0755;
    hash("new", 3, m.files[0].sha256);
}
static int archive(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/archive", root);
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(fd >= 0);
    tar_len += 1024;
    assert(write(fd, tar, tar_len) == (ssize_t)tar_len);
    m.packages[0].size = tar_len;
    hash(tar, tar_len, m.packages[0].sha256);
    return fd;
}
static void active_unchanged(void) {
    char path[512], buf[4] = {0};
    snprintf(path, sizeof(path), "%s/active", root);
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    assert(read(fd, buf, 3) == 3);
    close(fd);
    unsigned char before[32], after[32];
    hash("old", 3, before);
    hash(buf, 3, after);
    assert(!memcmp(before, after, 32));
}
static void empty_stage(void) {
    DIR *d = fdopendir(openat(ctx.staging_dirfd, ".", O_RDONLY | O_DIRECTORY));
    assert(d);
    struct dirent *e;
    while ((e = readdir(d)))
        assert(!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."));
    closedir(d);
}
static void reject(const char *label) {
    int fd = archive();
    d2ku_rc rc = d2ku_stage(&ctx, &m, fd);
    if (rc == D2KU_OK)
        fprintf(stderr, "accepted bad archive: %s\n", label);
    assert(rc != D2KU_OK);
    close(fd);
    active_unchanged();
    empty_stage();
}
static unsigned sync_count, fail_sync;
static d2ku_rc sync_fail(void *arg, int fd) {
    (void)arg;
    if (++sync_count == fail_sync)
        return D2KU_IO;
    return fsync(fd) ? D2KU_IO : D2KU_OK;
}
int main(void) {
    assert(mkdtemp(root));
    char path[512];
    snprintf(path, sizeof(path), "%s/stage", root);
    assert(mkdir(path, 0700) == 0);
    ctx.root_dirfd = -1;
    ctx.staging_dirfd = open(path, O_RDONLY | O_DIRECTORY);
    assert(ctx.staging_dirfd >= 0);
    strcpy(ctx.abi, "arm64");
    ctx.updater_version = ctx.wire_version = ctx.state_version = 1;
    snprintf(path, sizeof(path), "%s/active", root);
    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    assert(fd >= 0);
    assert(write(fd, "old", 3) == 3);
    close(fd);
    fixture();
    entry("../config", '0', "new", 3, 0755);
    reject("traversal");
    fixture();
    entry("/config", '0', "new", 3, 0755);
    reject("absolute");
    const char types[] = {'1', '2', '3', '4', '6', 'x', 'g', 'L', 'K'};
    for (size_t i = 0; i < sizeof(types); i++) {
        fixture();
        entry("bin/d2kc", types[i], "new", 3, 0755);
        reject("link/device/extension");
    }
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    entry("bin/d2kc", '0', "new", 3, 0755);
    reject("duplicate");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    entry("bin/extra", '0', "new", 3, 0755);
    reject("extra file");
    fixture();
    entry("else/", '5', NULL, 0, 0755);
    entry("bin/d2kc", '0', "new", 3, 0755);
    reject("unknown directory");
    fixture();
    entry("bin/", '5', NULL, 0, 0755);
    entry("bin/", '5', NULL, 0, 0755);
    entry("bin/d2kc", '0', "new", 3, 0755);
    reject("duplicate directory");
    fixture();
    entry("bin/d2kc", '0', "bad", 3, 0755);
    reject("file hash");
    fixture();
    entry("bin/d2kc", '0', "new!", 4, 0755);
    reject("file size");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0777);
    reject("world write");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 04755);
    reject("setuid");
    fixture();
    reject("missing file");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    tar[0] ^= 1;
    reject("header checksum");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    tar[257] = 'X';
    checksum(tar);
    reject("not ustar");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    tar[1024] = 1;
    reject("nonzero trailer");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    m.wire = 2;
    reject("incompatible");
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    m.packages[0].sha256[0] ^= 1;
    assert(d2ku_stage(&ctx, &m, fd) != D2KU_OK);
    close(fd);
    empty_stage();
    active_unchanged();
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    assert(ftruncate(fd, tar_len - 1) == 0);
    assert(d2ku_stage(&ctx, &m, fd) != D2KU_OK);
    close(fd);
    empty_stage();
    active_unchanged();
    for (fail_sync = 1; fail_sync <= 3; fail_sync++) {
        fixture();
        entry("bin/d2kc", '0', "new", 3, 0755);
        fd = archive();
        sync_count = 0;
        ctx.sync_fd = sync_fail;
        assert(d2ku_stage(&ctx, &m, fd) == D2KU_IO);
        ctx.sync_fd = NULL;
        close(fd);
        empty_stage();
        active_unchanged();
    }
    /* Correct artifact hash/size cannot make an incomplete ustar valid. */
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    assert(ftruncate(fd, (off_t)tar_len - 512) == 0);
    m.packages[0].size = tar_len - 512;
    hash(tar, tar_len - 512, m.packages[0].sha256);
    assert(d2ku_stage(&ctx, &m, fd) != D2KU_OK);
    close(fd);
    empty_stage();
    active_unchanged();
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    m.packages[0].size += 512;
    assert(d2ku_stage(&ctx, &m, fd) != D2KU_OK);
    close(fd);
    empty_stage();
    active_unchanged();
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    assert(symlinkat("../active", ctx.staging_dirfd, "bin") == 0);
    assert(d2ku_stage(&ctx, &m, fd) != D2KU_OK);
    close(fd);
    active_unchanged();
    assert(unlinkat(ctx.staging_dirfd, "bin", 0) == 0);
    fixture();
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    assert(d2ku_stage(&ctx, &m, fd) == D2KU_OK);
    close(fd);
    assert(unlinkat(ctx.staging_dirfd, "bin/d2kc", 0) == 0);
    assert(unlinkat(ctx.staging_dirfd, "bin", AT_REMOVEDIR) == 0);
    /* Every path is relative to private staging, with exact mode/hash on success. */
    fixture();
    entry("bin/", '5', NULL, 0, 0755);
    entry("bin/d2kc", '0', "new", 3, 0755);
    fd = archive();
    assert(d2ku_stage(&ctx, &m, fd) == D2KU_OK);
    close(fd);
    fd = openat(ctx.staging_dirfd, "bin/d2kc", O_RDONLY);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0755);
    char b[4] = {0};
    assert(read(fd, b, 3) == 3 && !strcmp(b, "new"));
    close(fd);
    active_unchanged();
    assert(unlinkat(ctx.staging_dirfd, "bin/d2kc", 0) == 0);
    assert(unlinkat(ctx.staging_dirfd, "bin", AT_REMOVEDIR) == 0);
    /* The selected second ABI uses a nonzero flat range and nested tree. */
    fixture();
    m.package_count = m.file_count = 2;
    m.files[1] = m.files[0];
    strcpy(m.files[1].path, "panel/fonts/font.woff2");
    m.files[1].path_len = strlen(m.files[1].path);
    m.files[1].mode = 0644;
    entry("panel/fonts/font.woff2", '0', "new", 3, 0644);
    fd = archive();
    m.packages[1] = m.packages[0];
    m.packages[1].file_offset = 1;
    strcpy(m.packages[0].abi, "amd64");
    m.packages[0].abi_len = 5;
    assert(d2ku_stage(&ctx, &m, fd) == D2KU_OK);
    close(fd);
    fd = openat(ctx.staging_dirfd, "panel/fonts/font.woff2", O_RDONLY);
    assert(fd >= 0);
    memset(b, 0, sizeof b);
    assert(read(fd, b, 3) == 3 && !strcmp(b, "new"));
    assert(fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0644);
    close(fd);
    assert(faccessat(ctx.staging_dirfd, "bin/d2kc", F_OK, 0) != 0);
    active_unchanged();
    assert(unlinkat(ctx.staging_dirfd, "panel/fonts/font.woff2", 0) == 0);
    assert(unlinkat(ctx.staging_dirfd, "panel/fonts", AT_REMOVEDIR) == 0);
    assert(unlinkat(ctx.staging_dirfd, "panel", AT_REMOVEDIR) == 0);
    close(ctx.staging_dirfd);
    snprintf(path, sizeof(path), "%s/stage", root);
    assert(rmdir(path) == 0);
    snprintf(path, sizeof(path), "%s/active", root);
    assert(unlink(path) == 0);
    snprintf(path, sizeof(path), "%s/archive", root);
    assert(unlink(path) == 0);
    assert(rmdir(root) == 0);
    puts("package: strict ustar failures preserve active; bounded, synced staging OK");
    return 0;
}
