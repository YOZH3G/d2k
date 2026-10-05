#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_update.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    d2ku_ctx c;
    d2ku_request r;
    d2ku_manifest m;
    d2ku_index i;
    uint64_t now;
    int stops, starts, failed, recovery_fail, crash_phase, probe_fail,
        probe_active, require_live, late_state, sync_count, crash_sync,
        fail_sync;
    int restart_candidate;
    /* Candidate services report ready only from this fixture time on:
       a real daemon needs seconds to connect, write heartbeat and listen. */
    uint64_t ready_at;
    char path[128];
} fixture;
static void put(int dir, const char *p, const char *s) {
    int fd = openat(dir, p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    assert(write(fd, s, strlen(s)) == (ssize_t)strlen(s));
    assert(close(fd) == 0);
}
static void check_file(int dir, const char *p, const char *s) {
    char b[128] = {0};
    int fd = openat(dir, p, O_RDONLY);
    assert(fd >= 0);
    assert(read(fd, b, sizeof b - 1) >= 0);
    close(fd);
    assert(!strcmp(b, s));
}
static void current(fixture *f, const char *s) {
    char b[128] = {0};
    assert(readlinkat(f->c.root_dirfd, "current", b, sizeof b - 1) > 0);
    assert(!strcmp(b, s));
}
static void rm_tree(int d) {
    DIR *dp = fdopendir(dup(d));
    assert(dp);
    struct dirent *e;
    while ((e = readdir(dp))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        int sub = openat(d, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (sub >= 0) {
            rm_tree(sub);
            close(sub);
            assert(!unlinkat(d, e->d_name, AT_REMOVEDIR));
        } else
            assert(!unlinkat(d, e->d_name, 0));
    }
    closedir(dp);
}
static d2ku_rc mono(void *p, uint64_t *n) {
    *n = ((fixture *)p)->now * 1000000;
    return D2KU_OK;
}
static d2ku_rc wall(void *p, int64_t *n) {
    (void)p;
    *n = 1791060000;
    return D2KU_OK;
}
static d2ku_rc clock_sample(void *p, d2ku_clock_sample *s) {
    memset(s, 0, sizeof *s);
    s->utc_seconds = 1791060000;
    s->mono_ms = ((fixture *)p)->now;
    s->local_date = 20261004;
    s->local_minute = 240;
    s->synchronized = 1;
    strcpy(s->boot_id, "test-boot");
    strcpy(s->timezone, "UTC");
    return D2KU_OK;
}
static d2ku_rc capture(void *p, uint64_t *n) {
    (void)p;
    *n = 4;
    return D2KU_OK;
}
static d2ku_rc service(void *p, const char *action, const char *id,
                       uint64_t enabled) {
    fixture *f = p;
    assert(enabled == 4);
    if (!strcmp(action, "stop")) {
        if (f->late_state) {
            mkdirat(f->c.root_dirfd, "state", 0700);
            put(f->c.root_dirfd, "state/knowledge", "quiesced");
            f->late_state = 0;
        }
        f->stops++;
        put(f->c.root_dirfd, "service", "stopped");
        return D2KU_OK;
    }
    if (!strcmp(action, "remove-rules"))
        return D2KU_OK;
    assert(!strcmp(action, "start"));
    f->starts++;
    if ((!strcmp(id, "B") && f->failed) ||
        (!strcmp(id, "A") && f->recovery_fail))
        return D2KU_HEALTH;
    put(f->c.root_dirfd, "service", id);
    if (!strcmp(id, "B"))
        put(f->c.root_dirfd, "state/knowledge", "candidate");
    return D2KU_OK;
}
static d2ku_rc offline(void *p, int fd, const char *id) {
    (void)p;
    (void)fd;
    assert(!strcmp(id, "B"));
    return D2KU_OK;
}
static d2ku_rc probe(void *p, const char *action, const char *id) {
    fixture *f = p;
    (void)id;
    if (!strcmp(action, "start"))
        f->probe_active = 1;
    if (!strcmp(action, "stop"))
        f->probe_active = 0;
    return f->probe_fail && !strcmp(action, "poll") ? D2KU_HEALTH : D2KU_OK;
}
static d2ku_rc wait_ms(void *p, unsigned n) {
    ((fixture *)p)->now += n;
    if (((fixture *)p)->restart_candidate && ((fixture *)p)->now > 1000000)
        return D2KU_IO;
    return D2KU_OK;
}
static d2ku_rc obs(void *p, unsigned svc, const d2ku_journal *j,
                   d2ku_health_observation *o) {
    fixture *f = p;
    assert(svc == 2);
    memset(o, 0, sizeof *o);
    o->pid = 123;
    o->start_ticks =
        f->restart_candidate && !strcmp(j->new_release_id, "B") ? f->now : 5;
    o->heartbeat_mono_ms = f->now;
    o->wire = 13;
    o->ready = !strcmp(j->new_release_id, "B") && f->now < f->ready_at ? 0 : 1;
    o->executable_matches = 1;
    strcpy(o->boot_id, "test-boot");
    strcpy(o->release_id, j->new_release_id);
    return D2KU_OK;
}
static d2ku_rc ok(void *p) {
    (void)p;
    return D2KU_OK;
}
static d2ku_rc sync_crash(void *p, int fd) {
    fixture *f = p;
    assert(!fsync(fd));
    f->sync_count++;
    if (f->fail_sync == f->sync_count)
        return D2KU_IO;
    if (f->crash_sync == f->sync_count)
        _exit(77);
    if (f->require_live) {
        d2ku_journal j;
        if (d2ku_journal_load(&f->c, &j) == D2KU_OK &&
            j.phase == D2KU_COMMITTED && !f->probe_active)
            return D2KU_IO;
    }
    if (f->crash_phase) {
        d2ku_journal j;
        if (d2ku_journal_load(&f->c, &j) == D2KU_OK &&
            (int)j.phase == f->crash_phase)
            _exit(77);
    }
    return D2KU_OK;
}
static void sha(const void *p, size_t n, unsigned char out[32]) {
    unsigned z;
    assert(EVP_Digest(p, n, out, &z, EVP_sha256(), NULL) == 1 && z == 32);
}
static void setup(fixture *f) {
    memset(f, 0, sizeof *f);
    strcpy(f->path, "/tmp/d2ku-transaction-XXXXXX");
    assert(mkdtemp(f->path));
    f->c.root_dirfd = open(f->path, O_RDONLY | O_DIRECTORY);
    assert(f->c.root_dirfd >= 0);
    f->now = 1000;
    f->c.clock = (d2ku_clock){
        .arg = f, .wall = wall, .monotonic = mono, .snapshot = clock_sample};
    f->c.wire_version = 13;
    f->c.state_version = 1;
    f->c.updater_version = 1;
    strcpy(f->c.abi, "amd64");
    f->c.has_accepted_index = 1;
    f->c.accepted_sequence = 1;
    memset(f->c.accepted_index_sha256, 3, 32);
    f->c.transaction = (d2ku_transaction_ops){.arg = f,
                                              .capture = capture,
                                              .services = service,
                                              .offline = offline,
                                              .updater_probe = probe,
                                              .wait_ms = wait_ms,
                                              .path_count = 2};
    strcpy(f->c.transaction.paths[0].name, "config");
    f->c.transaction.paths[0].configuration = 1;
    strcpy(f->c.transaction.paths[1].name, "state");
    f->c.health_arg = f;
    f->c.health_observe = obs;
    f->c.health_http = ok;
    f->c.io_arg = f;
    d2ku_persistent_state policy = {0};
    policy.schema = 1;
    policy.sequence = 1;
    policy.has_accepted_index = 1;
    policy.accepted_sequence = 1;
    memset(policy.accepted_index_sha256, 3, 32);
    policy.trust_count = 1;
    policy.trust[0].not_after = 1792000000;
    assert(d2ku_persistent_store(&f->c, &policy) == D2KU_OK);
    assert(!mkdirat(f->c.root_dirfd, "releases", 0700));
    int releases = openat(f->c.root_dirfd, "releases", O_RDONLY | O_DIRECTORY);
    assert(!mkdirat(releases, "A", 0700));
    close(releases);
    assert(!symlinkat("releases/A", f->c.root_dirfd, "current"));
    assert(!mkdirat(f->c.root_dirfd, "state", 0700));
    put(f->c.root_dirfd, "state/knowledge", "original");
    put(f->c.root_dirfd, "config", "personal");
    put(f->c.root_dirfd, "service", "A");
    /* A signed release carries its own updater; rollback needs it. */
    put(f->c.root_dirfd, "releases/A/d2k-update", "updater");
    unsigned char h[32];
    memset(h, 1, 32);
    assert(d2ku_release_receipt(&f->c, "A", h) == D2KU_OK);
    strcpy(f->r.transaction_id, "operation-1");
    strcpy(f->r.expected_release_id, "A");
    memset(f->r.expected_manifest_sha256, 1, 32);
    strcpy(f->r.release_id, "B");
    memset(f->r.manifest_sha256, 2, 32);
    f->r.manifest = &f->m;
    f->r.index = &f->i;
    f->i.schema = 1;
    f->i.sequence = 1;
    f->i.issued_at = 1791000000;
    f->i.expires_at = 1792000000;
    strcpy(f->i.release_id, "B");
    f->i.release_id_len = 1;
    memset(f->i.document_sha256, 3, 32);
    memset(f->i.manifest_sha256, 2, 32);
    f->m.schema = 1;
    f->m.min_updater = 1;
    f->m.wire = 13;
    f->m.state = 1;
    strcpy(f->m.release_id, "B");
    f->m.release_id_len = 1;
    memset(f->m.document_sha256, 2, 32);
    f->m.package_count = 1;
    f->m.file_count = 1;
    strcpy(f->m.packages[0].abi, "amd64");
    f->m.packages[0].abi_len = 5;
    f->m.packages[0].file_count = 1;
    f->m.packages[0].size = 2048;
    strcpy(f->m.packages[0].artifact, "B.tar");
    f->m.packages[0].artifact_len = 5;
    strcpy(f->m.files[0].path, "d2k-update");
    f->m.files[0].path_len = 10;
    f->m.files[0].mode = 0755;
    f->m.files[0].size = 3;
    sha("bin", 3, f->m.files[0].sha256);
    unsigned char tar[2048] = {0};
    memcpy(tar, "d2k-update", 10);
    snprintf((char *)tar + 100, 8, "%07o", 0755);
    snprintf((char *)tar + 108, 8, "%07o", 0);
    snprintf((char *)tar + 116, 8, "%07o", 0);
    snprintf((char *)tar + 124, 12, "%011o", 3);
    snprintf((char *)tar + 136, 12, "%011o", 0);
    memset(tar + 148, ' ', 8);
    tar[156] = '0';
    memcpy(tar + 257,
           "ustar\0"
           "00",
           8);
    unsigned sum = 0;
    for (int k = 0; k < 512; k++)
        sum += tar[k];
    snprintf((char *)tar + 148, 7, "%06o", sum);
    tar[155] = ' ';
    memcpy(tar + 512, "bin", 3);
    sha(tar, sizeof tar, f->m.packages[0].sha256);
    f->r.archive_fd =
        openat(f->c.root_dirfd, "archive", O_RDWR | O_CREAT | O_EXCL, 0600);
    assert(f->r.archive_fd >= 0);
    assert(write(f->r.archive_fd, tar, sizeof tar) == sizeof tar);
}
static void cleanup(fixture *f) {
    close(f->r.archive_fd);
    rm_tree(f->c.root_dirfd);
    close(f->c.root_dirfd);
    assert(!rmdir(f->path));
}
