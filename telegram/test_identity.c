#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_identity.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void bytes(const char *path, unsigned char out[88]) {
    FILE *f = fopen(path, "rb");
    assert(f && fread(out, 1, 88, f) == 88);
    assert(fgetc(f) == EOF);
    assert(fclose(f) == 0);
}
int main(void) {
    char dir[] = "/tmp/d2k-identity-XXXXXX", path[256], link[256];
    unsigned char before[88], after[88];
    tg_identity first, second;
    assert(mkdtemp(dir));
    snprintf(path, sizeof path, "%s/identity", dir);
    snprintf(link, sizeof link, "%s/link", dir);
    assert(tg_identity_load_or_mint(path, &first) == 0);
    assert(tg_identity_load_or_mint(path, &second) == 0);
    assert(strcmp(first.install_id_hex, second.install_id_hex) == 0);
    tg_identity_cleanup(&second);
    bytes(path, before);
    assert(chmod(path, 0644) == 0);
    assert(tg_identity_load_or_mint(path, &second) == -1);
    assert(!second.private_key && !second.install_id_hex[0]);
    bytes(path, after); assert(memcmp(before, after, 88) == 0);
    assert(chmod(path, 0600) == 0);
    assert(symlink(path, link) == 0);
    assert(tg_identity_load_or_mint(link, &second) == -1);
    struct stat st; assert(lstat(link, &st) == 0 && S_ISLNK(st.st_mode));
    FILE *f = fopen(path, "r+b"); assert(f);
    assert(fputc('X', f) != EOF && fclose(f) == 0);
    bytes(path, before);
    FILE *log = tmpfile(); assert(log);
    int saved_stderr = dup(STDERR_FILENO); assert(saved_stderr >= 0);
    assert(dup2(fileno(log), STDERR_FILENO) >= 0);
    assert(tg_identity_load_or_mint(path, &second) == -1);
    assert(fflush(stderr) == 0 && dup2(saved_stderr, STDERR_FILENO) >= 0);
    close(saved_stderr);
    rewind(log); char message[1024] = {0};
    assert(fread(message, 1, sizeof message - 1, log) > 0); fclose(log);
    assert(strstr(message, path) && strstr(message, "повреждён заголовок"));
    assert(strstr(message, "удалите") && strstr(message, "install_id изменится"));
    bytes(path, after); assert(memcmp(before, after, 88) == 0);
    assert(truncate(path, 12) == 0);
    assert(tg_identity_load_or_mint(path, &second) == -1);
    assert(stat(path, &st) == 0 && st.st_size == 12);
    tg_identity_cleanup(&first);
    unlink(link); unlink(path); rmdir(dir);
    puts("identity: missing, persistent, unsafe, symlink and corrupt files PASS");
    return 0;
}
