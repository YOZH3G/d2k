#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <sys/stat.h>
#include <unistd.h>
static int test_fsync(int fd);
#define fsync test_fsync
#include "catalog.c"
#undef fsync
#include <assert.h>
static int file_calls, dir_calls, fail_file, fail_dir;
static int test_fsync(int fd) {
    struct stat st; assert(fstat(fd, &st) == 0);
    if (S_ISDIR(st.st_mode)) { ++dir_calls; if (fail_dir) { errno = EIO; return -1; } }
    else { ++file_calls; if (fail_file) { errno = EIO; return -1; } }
    return fsync(fd);
}
int main(void) {
    (void)test_fsync;
    char dir[] = "/tmp/d2k-durable-XXXXXX", path[256], tmp[264], err[256];
    d2k_catalog cat; memset(&cat, 0, sizeof cat);
    assert(mkdtemp(dir)); snprintf(path, sizeof path, "%s/catalog.json", dir);
    snprintf(tmp, sizeof tmp, "%s.new", path);
    FILE *f = fopen(path, "w"); assert(f); assert(fputs("original", f) >= 0); assert(fclose(f) == 0);
    fail_file = 1;
    assert(d2k_catalog_save_atomic(&cat, path, err, sizeof err) == -1);
    f = fopen(path, "r"); assert(f); char text[16]; assert(fgets(text, sizeof text, f)); fclose(f);
    assert(strcmp(text, "original") == 0 && access(tmp, F_OK) == -1);
    fail_file = 0; fail_dir = 1;
    assert(d2k_catalog_save_atomic(&cat, path, err, sizeof err) == -1);
    assert(dir_calls == 1);
    fail_dir = 0;
    assert(d2k_catalog_save_atomic(&cat, path, err, sizeof err) == 0);
    assert(file_calls == 3 && dir_calls == 2);
    d2k_catalog loaded; assert(d2k_catalog_load(path, &loaded, err, sizeof err) == 0);
    d2k_catalog_free(&loaded); unlink(path); rmdir(dir);
    puts("catalog: file fsync, rename, directory fsync and error propagation PASS");
    return 0;
}
