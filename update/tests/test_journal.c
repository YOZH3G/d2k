#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_update.h"
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static d2ku_journal record(unsigned seq)
{
    d2ku_journal j = {0};
    j.schema = 1; j.sequence = seq; j.phase = D2KU_PREPARED;
    j.failure_reason = D2KU_HEALTH; j.recovery_reason = D2KU_IO;
    strcpy(j.transaction_id, "operation-1"); j.transaction_id_len = 11;
    strcpy(j.old_release_id, "old"); j.old_release_id_len = 3;
    strcpy(j.new_release_id, "new"); j.new_release_id_len = 3;
    memset(j.old_manifest_sha256, 1, 32); memset(j.new_manifest_sha256, 2, 32);
    j.active_services = 5; j.progress_mono_ms = 100; j.progress_utc = 200;
    strcpy(j.progress_boot_id, "boot-1"); j.progress_boot_id_len = 6;
    return j;
}
static d2ku_ctx context(char path[64])
{
    d2ku_ctx c = {0}; strcpy(path, "/tmp/d2ku-journal-XXXXXX");
    assert(mkdtemp(path)); c.root_dirfd = open(path, O_RDONLY | O_DIRECTORY);
    assert(c.root_dirfd >= 0); return c;
}
static void cleanup(d2ku_ctx *c, const char *path)
{
    int d = openat(c->root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
    if (d >= 0) {
        const char *names[] = {"journal.0", "journal.1", "persistent.0", "persistent.1",
            "maintenance.lock", "journal.lock", "persistent.lock", ".unrelated-temp"};
        for (size_t i = 0; i < sizeof(names)/sizeof(*names); i++) unlinkat(d, names[i], 0);
        DIR *listing = fdopendir(dup(d)); assert(listing);
        struct dirent *entry;
        while ((entry = readdir(listing)))
            if (!strncmp(entry->d_name, ".journal-", 9) || !strncmp(entry->d_name, ".persistent-", 12))
                assert(unlinkat(d, entry->d_name, 0) == 0);
        closedir(listing);
        close(d); assert(unlinkat(c->root_dirfd, "update-state", AT_REMOVEDIR) == 0);
    }
    close(c->root_dirfd); assert(rmdir(path) == 0);
}
static void damage(d2ku_ctx *c, const char *name, int truncate_record)
{
    int d = openat(c->root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
    int fd = openat(d, name, O_WRONLY); assert(fd >= 0);
    if (truncate_record) assert(ftruncate(fd, 3) == 0);
    else { unsigned char byte = 0xff; assert(pwrite(fd, &byte, 1, 70) == 1); }
    close(fd); close(d);
}
static void generations(void)
{
    char path[64]; d2ku_ctx c = context(path); d2ku_journal j = record(1), out, sentinel;
    memset(&sentinel, 0x5a, sizeof sentinel); out = sentinel;
    assert(d2ku_journal_load(&c, &out) == D2KU_ABSENT);
    assert(!memcmp(&out, &sentinel, sizeof out));
    assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    assert(d2ku_journal_load(&c, &out) == D2KU_OK && out.sequence == 1);
    assert(out.active_services == 5 && out.transaction_id_len == 11);
    assert(out.failure_reason == D2KU_HEALTH && out.recovery_reason == D2KU_IO);
    /* C-only tail/checksum bytes are excluded; equal logical retry is identical. */
    memset(j.checksum, 0xab, sizeof j.checksum);
    memset(j.transaction_id + 12, 0xcc, sizeof j.transaction_id - 12);
    assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    for (unsigned n = 2; n <= 9; n++) {
        j.sequence = n; j.progress_mono_ms = n * 100;
        assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    }
    /* Odd sequence uses slot 1. Torn newest falls back to previous valid slot. */
    damage(&c, "journal.1", 1);
    assert(d2ku_journal_load(&c, &out) == D2KU_OK && out.sequence == 8);
    j.sequence = 9; assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    damage(&c, "journal.1", 0);
    assert(d2ku_journal_load(&c, &out) == D2KU_OK && out.sequence == 8);
    damage(&c, "journal.0", 1); out = sentinel;
    assert(d2ku_journal_load(&c, &out) == D2KU_RECOVERY);
    assert(!memcmp(&out, &sentinel, sizeof out));
    assert(d2ku_journal_store(&c, &j) == D2KU_RECOVERY);
    cleanup(&c, path);
}
static void invalid_records(void)
{
    char path[64]; d2ku_ctx c = context(path); d2ku_journal j = record(1);
    j.schema = 2; assert(d2ku_journal_store(&c, &j) == D2KU_INCOMPATIBLE);
    j = record(1); strcpy(j.transaction_id, "../evil"); j.transaction_id_len = 7;
    assert(d2ku_journal_store(&c, &j) == D2KU_INVALID);
    j = record(1); j.old_release_id_len = 4;
    assert(d2ku_journal_store(&c, &j) == D2KU_INVALID);
    j = record(1); j.phase = D2KU_SWITCHING;
    assert(d2ku_journal_store(&c, &j) == D2KU_INVALID);
    j.snapshot_ready = 1; assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    j.sequence = 0; assert(d2ku_journal_store(&c, &j) == D2KU_INVALID);
    j.sequence = 3; assert(d2ku_journal_store(&c, &j) == D2KU_REPLAY);
    j.sequence = 1; j.new_release_id[0] = 'X';
    assert(d2ku_journal_store(&c, &j) == D2KU_REPLAY);
    cleanup(&c, path);
}
static int fault, writes;
static ino_t state_ino;
static ssize_t injected_write(void *arg, int fd, const void *bytes, size_t len)
{
    (void)arg;
    if (fault == 1 && ++writes == 2) { errno = ENOSPC; return -1; }
    return write(fd, bytes, len > 17 ? 17 : len); /* exercise partial writes */
}
static d2ku_rc injected_sync(void *arg, int fd)
{
    struct stat st; (void)arg; assert(fstat(fd, &st) == 0);
    if ((fault == 2 && S_ISREG(st.st_mode)) || (fault == 4 && S_ISDIR(st.st_mode) && st.st_ino == state_ino))
        return D2KU_IO;
    return fsync(fd) == 0 ? D2KU_OK : D2KU_IO;
}
static d2ku_rc injected_rename(void *arg, int from, const char *src, int to, const char *dst)
{
    (void)arg; if (fault == 3) return D2KU_IO;
    return renameat(from, src, to, dst) == 0 ? D2KU_OK : D2KU_IO;
}
static void faults(void)
{
    for (fault = 1; fault <= 4; fault++) {
        char path[64]; d2ku_ctx c = context(path); d2ku_journal j = record(1), out;
        assert(d2ku_journal_store(&c, &j) == D2KU_OK);
        int d = openat(c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
        int f = openat(d, ".unrelated-temp", O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(f >= 0); close(f);
        struct stat ds; assert(fstat(d, &ds) == 0); state_ino = ds.st_ino;
        c.write_fd = injected_write; c.sync_fd = injected_sync; c.rename_at = injected_rename;
        writes = 0; j.sequence = 2; j.phase = D2KU_COMMITTED; j.snapshot_ready = 1;
        int committed = d2ku_journal_store(&c, &j) == D2KU_OK;
        assert(committed == 0);
        assert(faccessat(d, ".unrelated-temp", F_OK, 0) == 0); close(d);
        assert(d2ku_journal_load(&c, &out) == D2KU_OK);
        assert(out.sequence == (fault == 4 ? 2u : 1u));
        if (fault == 4) assert(d2ku_journal_store(&c, &j) == D2KU_IO);
        c.write_fd = NULL; c.sync_fd = NULL; c.rename_at = NULL;
        /* Retry visible-but-unsynced exact generation must perform durability again. */
        assert(d2ku_journal_store(&c, &j) == D2KU_OK);
        assert(d2ku_journal_load(&c, &out) == D2KU_OK && out.sequence == 2);
        cleanup(&c, path);
    }
    fault = 0;
}
static void lock_crash(void)
{
    char path[64]; d2ku_ctx c = context(path); int fd = -1;
    assert(d2ku_maintenance_lock(&c, &fd) == D2KU_OK && fd >= 0);
    assert((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    pid_t p = fork(); assert(p >= 0);
    if (!p) { int other = -1; d2ku_maintenance_unlock(fd);
        _exit(d2ku_maintenance_lock(&c, &other) == D2KU_BUSY ? 0 : 1); }
    int s; assert(waitpid(p, &s, 0) == p && WIFEXITED(s) && WEXITSTATUS(s) == 0);
    d2ku_maintenance_unlock(fd);
    p = fork(); assert(p >= 0);
    if (!p) { int own; if (d2ku_maintenance_lock(&c, &own) != D2KU_OK) _exit(1);
        _exit(0); /* no explicit close: kernel must release */ }
    assert(waitpid(p, &s, 0) == p && WEXITSTATUS(s) == 0);
    assert(d2ku_maintenance_lock(&c, &fd) == D2KU_OK);
    d2ku_maintenance_unlock(fd); cleanup(&c, path);
}
static void separate_state(void)
{
    char path[64]; d2ku_ctx c = context(path); d2ku_persistent_state s = {0}, out;
    s.schema = 1; s.sequence = 1; s.has_accepted_index = 1; s.accepted_sequence = 50;
    memset(s.accepted_index_sha256, 7, 32); s.last_accepted_timestamp = 300;
    s.trust_count = 1; memset(s.trust[0].public_key, 8, 32);
    s.trust[0].not_before = 100; s.trust[0].not_after = 900;
    s.policy.enabled = 1; s.policy.selected_date = 20261004; s.policy.selected_minute = 234;
    s.policy.last_attempt_date = 20261004; s.policy.has_quarantined_release = 1;
    memset(s.policy.quarantined_release_sha256, 9, 32);
    assert(d2ku_persistent_store(&c, &s) == D2KU_OK);
    d2ku_journal j = record(1); assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    j.sequence = 2; j.phase = D2KU_ROLLED_BACK; assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    int d = openat(c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
    unlinkat(d, "journal.0", 0); unlinkat(d, "journal.1", 0); close(d);
    assert(d2ku_persistent_load(&c, &out) == D2KU_OK);
    assert(out.accepted_sequence == 50 && out.trust_count == 1 && out.policy.selected_minute == 234);
    s.sequence = 2; assert(d2ku_persistent_store(&c, &s) == D2KU_OK);
    damage(&c, "persistent.0", 1);
    assert(d2ku_persistent_load(&c, &out) == D2KU_OK && out.sequence == 1);
    damage(&c, "persistent.1", 0);
    assert(d2ku_persistent_load(&c, &out) == D2KU_RECOVERY);
    cleanup(&c, path);
}

static void wire_validation(void)
{
    for (unsigned variant = 0; variant < 7; variant++) {
        char path[64]; d2ku_ctx c = context(path); d2ku_journal j = record(1), out;
        assert(d2ku_journal_store(&c, &j) == D2KU_OK);
        int d = openat(c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
        int f = openat(d, "journal.1", O_RDWR); assert(f >= 0);
        unsigned char raw[4096]; ssize_t len = read(f, raw, sizeof raw); assert(len > 100);
        /* Recompute valid checksum: these must fail semantic decoding, not only
         * detect random bit damage. Format offsets come from public FORMAT. */
        if (variant == 0) raw[11] = 2; /* unknown schema */
        if (variant == 1) memcpy(raw, "D2KPER01", 8); /* wrong record identity */
        if (variant == 2) raw[58] = '/'; /* invalid transaction ID */
        if (variant == 3) raw[23] = 2; /* wrong sequence for slot */
        if (variant == 4) { raw[len++] = 0; raw[15] = (unsigned char)len; } /* trailing byte */
        if (variant == 5) raw[71] = 255; /* invalid phase (body + tx + phase) */
        if (variant == 6) raw[80] = '/'; /* malformed new release ID */
        memset(raw + 24, 0, 32); unsigned char hash[32]; unsigned n;
        assert(EVP_Digest(raw, (size_t)len, hash, &n, EVP_sha256(), NULL) == 1 && n == 32);
        memcpy(raw + 24, hash, 32);
        assert(pwrite(f, raw, (size_t)len, 0) == len); close(f); close(d);
        assert(d2ku_journal_load(&c, &out) == D2KU_RECOVERY);
        cleanup(&c, path);
    }
}
static int crash_point;
static ssize_t crash_write(void *arg, int fd, const void *bytes, size_t len)
{
    (void)arg;
    if (crash_point == 1) { assert(write(fd, bytes, 7) == 7); _exit(41); }
    return write(fd, bytes, len);
}
static d2ku_rc crash_sync(void *arg, int fd)
{
    (void)arg; struct stat st; assert(fstat(fd, &st) == 0);
    assert(fsync(fd) == 0);
    if (crash_point == 2 && S_ISREG(st.st_mode)) _exit(42);
    if (crash_point == 4 && S_ISDIR(st.st_mode) && st.st_ino == state_ino) _exit(44);
    return D2KU_OK;
}
static d2ku_rc crash_rename(void *arg, int from, const char *src, int to, const char *dst)
{
    (void)arg; assert(renameat(from, src, to, dst) == 0);
    if (crash_point == 3) _exit(43);
    return D2KU_OK;
}
static void crash_windows(void)
{
    for (crash_point = 1; crash_point <= 4; crash_point++) {
        char path[64]; d2ku_ctx c = context(path); d2ku_journal j = record(1), out;
        assert(d2ku_journal_store(&c, &j) == D2KU_OK);
        int d = openat(c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
        struct stat st; assert(fstat(d, &st) == 0); state_ino = st.st_ino; close(d);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            c.write_fd = crash_write; c.sync_fd = crash_sync; c.rename_at = crash_rename;
            j.sequence = 2; j.phase = D2KU_STOPPING;
            (void)d2ku_journal_store(&c, &j); _exit(1);
        }
        int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status));
        assert(WEXITSTATUS(status) == 40 + crash_point);
        assert(d2ku_journal_load(&c, &out) == D2KU_OK);
        assert(out.sequence == (crash_point <= 2 ? 1u : 2u));
        j.sequence = out.sequence + 1; assert(d2ku_journal_store(&c, &j) == D2KU_OK);
        cleanup(&c, path);
    }
}
static d2ku_persistent_state persistent_record(void)
{
    d2ku_persistent_state s = {0}; s.schema = 1; s.sequence = 1;
    s.has_accepted_index = 1; s.accepted_sequence = 50;
    memset(s.accepted_index_sha256, 7, 32); s.last_accepted_timestamp = 300;
    s.trust_count = 1; memset(s.trust[0].public_key, 8, 32);
    s.trust[0].not_before = 100; s.trust[0].not_after = 900;
    s.policy.enabled = 1; s.policy.selected_date = 20261004; s.policy.selected_minute = 234;
    s.policy.last_attempt_date = 20261004; return s;
}
static void trust_policy_floors(void)
{
    char path[64]; d2ku_ctx c = context(path); d2ku_persistent_state s = persistent_record(), next;
    assert(d2ku_persistent_store(&c, &s) == D2KU_OK);
    for (unsigned variant = 0; variant < 7; variant++) {
        next = s; next.sequence = 2;
        if (variant == 0) next.accepted_sequence--;
        if (variant == 1) next.accepted_index_sha256[0]++;
        if (variant == 2) next.last_accepted_timestamp--;
        if (variant == 3) next.trust[0].public_key[0]++;
        if (variant == 4) next.policy.last_attempt_date--;
        if (variant == 5) next.policy.selected_date--;
        if (variant == 6) next.policy.selected_minute++;
        assert(d2ku_persistent_store(&c, &next) == D2KU_REPLAY);
    }
    next = s; next.sequence = 2; next.accepted_sequence = 51;
    next.accepted_index_sha256[0]++; next.trust_count = 2;
    next.trust[1] = next.trust[0]; next.trust[1].public_key[0]++;
    assert(d2ku_persistent_store(&c, &next) == D2KU_OK);
    assert(d2ku_persistent_load(&c, &s) == D2KU_OK && s.accepted_sequence == 51 && s.trust_count == 2);
    cleanup(&c, path);
}
static void persistent_faults(void)
{
    for (fault = 1; fault <= 4; fault++) {
        char path[64]; d2ku_ctx c = context(path);
        d2ku_persistent_state s = persistent_record(), out;
        assert(d2ku_persistent_store(&c, &s) == D2KU_OK);
        int d = openat(c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
        struct stat st; assert(fstat(d, &st) == 0); state_ino = st.st_ino; close(d);
        c.write_fd = injected_write; c.sync_fd = injected_sync; c.rename_at = injected_rename;
        writes = 0; s.sequence = 2; s.accepted_sequence = 51;
        assert(d2ku_persistent_store(&c, &s) == D2KU_IO);
        assert(c.accepted_sequence == 0 && c.trust_count == 0); /* no activation */
        assert(d2ku_persistent_load(&c, &out) == D2KU_OK);
        assert(out.accepted_sequence == (fault == 4 ? 51u : 50u));
        c.write_fd = NULL; c.sync_fd = NULL; c.rename_at = NULL;
        assert(d2ku_persistent_store(&c, &s) == D2KU_OK);
        cleanup(&c, path);
    }
    fault = 0;
}


static ino_t unreadable_ino;
static int injected_stat(void *arg, int fd, struct stat *out)
{
    (void)arg;
    struct stat actual;
    assert(fstat(fd, &actual) == 0);
    if (actual.st_ino == unreadable_ino) { errno = EIO; return -1; }
    *out = actual; return 0;
}
static void stat_error_blocks_older_generation(void)
{
    char path[64]; d2ku_ctx c = context(path);
    d2ku_journal j = record(1), out, sentinel;
    assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    j.sequence = 2; assert(d2ku_journal_store(&c, &j) == D2KU_OK);
    int d = openat(c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
    int fd = openat(d, "journal.0", O_RDONLY); struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0); unreadable_ino = st.st_ino; close(fd);
    c.stat_fd = injected_stat;
    memset(&sentinel, 0x5a, sizeof sentinel); out = sentinel;
    /* A syscall failure inspecting newest must not expose older transaction. */
    assert(d2ku_journal_load(&c, &out) == D2KU_IO);
    assert(!memcmp(&out, &sentinel, sizeof out));
    c.stat_fd = NULL;
    d2ku_persistent_state state = persistent_record(), saved, loaded;
    assert(d2ku_persistent_store(&c, &state) == D2KU_OK);
    state.sequence = 2; state.accepted_sequence = 51;
    assert(d2ku_persistent_store(&c, &state) == D2KU_OK);
    fd = openat(d, "persistent.0", O_RDONLY);
    assert(fd >= 0 && fstat(fd, &st) == 0); unreadable_ino = st.st_ino; close(fd);
    c.stat_fd = injected_stat;
    memset(&saved, 0x6b, sizeof saved); loaded = saved;
    /* Same primitive must not expose a stale trust publication/floor. */
    assert(d2ku_persistent_load(&c, &loaded) == D2KU_IO);
    assert(!memcmp(&loaded, &saved, sizeof loaded));
    c.stat_fd = NULL; close(d); cleanup(&c, path);
}

int main(void)
{
    generations(); invalid_records(); faults(); lock_crash(); separate_state();
    wire_validation(); crash_windows(); trust_policy_floors(); persistent_faults();
    stat_error_blocks_older_generation();
    puts("journal tests: ok"); return 0;
}
