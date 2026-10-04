#include "transaction_fixture.h"
#include <time.h>
static void executable_archive(fixture *f, const char *path) {
    int binary = open(path, O_RDONLY);
    assert(binary >= 0);
    struct stat st;
    assert(!fstat(binary, &st) && st.st_size > 0);
    size_t bytes = (size_t)st.st_size,
           total = 512 + ((bytes + 511) / 512) * 512 + 1024;
    unsigned char *tar = calloc(1, total);
    assert(tar);
    assert(pread(f->r.archive_fd, tar, 512, 0) == 512);
    size_t used = 0;
    while (used < bytes) {
        ssize_t n = read(binary, tar + 512 + used, bytes - used);
        assert(n > 0);
        used += (size_t)n;
    }
    close(binary);
    snprintf((char *)tar + 124, 12, "%011llo", (unsigned long long)bytes);
    memset(tar + 148, ' ', 8);
    unsigned sum = 0;
    for (int k = 0; k < 512; k++)
        sum += tar[k];
    snprintf((char *)tar + 148, 7, "%06o", sum);
    tar[155] = ' ';
    f->m.files[0].size = bytes;
    sha(tar + 512, bytes, f->m.files[0].sha256);
    f->m.packages[0].size = total;
    sha(tar, total, f->m.packages[0].sha256);
    assert(!ftruncate(f->r.archive_fd, 0));
    assert(lseek(f->r.archive_fd, 0, SEEK_SET) == 0);
    assert(write(f->r.archive_fd, tar, total) == (ssize_t)total);
    free(tar);
}
static d2ku_rc selected_space(void *arg, uint64_t *bytes) {
    fixture *f = arg;
    struct stat st;
    *bytes = fstatat(f->c.root_dirfd, "releases/B", &st, 0) ? 35 : 32;
    return D2KU_OK;
}
static void space_accounting(void) {
    fixture f;
    d2ku_status s = {0};
    setup(&f);
    f.c.transaction.available_bytes = selected_space;
    f.m.package_count = 2;
    f.m.file_count = 2;
    f.m.packages[1] = f.m.packages[0];
    strcpy(f.m.packages[1].abi, "arm");
    f.m.packages[1].abi_len = 3;
    strcpy(f.m.packages[1].artifact, "arm.tar");
    f.m.packages[1].artifact_len = 7;
    f.m.packages[1].file_offset = 1;
    f.m.packages[1].size = 8192;
    f.m.files[1] = f.m.files[0];
    f.m.files[1].size = 4096;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_OK);
    cleanup(&f);
    setup(&f);
    f.r.expected_manifest_sha256[0] = 9;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_BUSY);
    f.r.expected_manifest_sha256[0] = 1;
    f.c.transaction.available_bytes = selected_space;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_OK);
    cleanup(&f);
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--boot-probe")) {
        char mode[16] = {0};
        int fd = openat(4, "probe-mode", O_RDONLY);
        if (fd >= 0) {
            assert(read(fd, mode, sizeof mode - 1) >= 0);
            close(fd);
        }
        if (!strcmp(mode, "fail"))
            return 7;
        if (d2ku_boot_pulse(3, 1) != D2KU_OK)
            return 8;
        while (d2ku_boot_pulse(3, 0) == D2KU_OK) {
            struct timespec t = {0, 1000000};
            nanosleep(&t, NULL);
        }
        return 0;
    }

    space_accounting();
    fixture f;
    d2ku_status s = {0};
    d2ku_journal j;
    setup(&f);
    f.m.state = 2;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_INCOMPATIBLE);
    assert(f.stops == 0);
    current(&f, "releases/A");
    cleanup(&f);
    setup(&f);
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_OK);
    assert(s.health_complete && f.now >= 121000);
    current(&f, "releases/B");
    check_file(f.c.root_dirfd, "service", "B");
    int stops = f.stops;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_OK);
    assert(f.stops == stops);
    assert(d2ku_journal_load(&f.c, &j) == D2KU_OK && j.phase == D2KU_COMMITTED);
    put(f.c.root_dirfd, "state/knowledge", "new knowledge");
    d2ku_persistent_state policy;
    assert(d2ku_persistent_load(&f.c, &policy) == D2KU_OK);
    policy.sequence++;
    policy.accepted_sequence = 9;
    assert(d2ku_persistent_store(&f.c, &policy) == D2KU_OK);
    strcpy(f.r.transaction_id, "rollback-1");
    strcpy(f.r.expected_release_id, "B");
    memset(f.r.expected_manifest_sha256, 2, 32);
    strcpy(f.r.release_id, "A");
    memset(f.r.manifest_sha256, 1, 32);
    assert(d2ku_rollback(&f.c, &f.r, &s) == D2KU_OK);
    current(&f, "releases/A");
    check_file(f.c.root_dirfd, "state/knowledge", "new knowledge");
    assert(d2ku_persistent_load(&f.c, &policy) == D2KU_OK &&
           policy.accepted_sequence == 9);
    cleanup(&f);
    setup(&f);
    f.failed = 1;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_HEALTH);
    current(&f, "releases/A");
    check_file(f.c.root_dirfd, "state/knowledge", "original");
    check_file(f.c.root_dirfd, "service", "A");
    assert(d2ku_journal_load(&f.c, &j) == D2KU_OK &&
           j.failure_reason == D2KU_HEALTH && j.recovery_reason == D2KU_OK);
    assert(d2ku_persistent_load(&f.c, &policy) == D2KU_OK &&
           policy.accepted_sequence == 1 &&
           policy.policy.has_quarantined_release);
    assert(!memcmp(policy.policy.quarantined_release_sha256,
                   f.r.manifest_sha256, 32));
    cleanup(&f);
    setup(&f);
    f.probe_fail = 1;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_HEALTH);
    current(&f, "releases/A");
    cleanup(&f);
    setup(&f);
    f.require_live = 1;
    f.c.sync_fd = sync_crash;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_OK);
    cleanup(&f);
    setup(&f);
    assert(!unlinkat(f.c.root_dirfd, "state/knowledge", 0));
    assert(!unlinkat(f.c.root_dirfd, "state", AT_REMOVEDIR));
    f.late_state = 1;
    f.failed = 1;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_HEALTH);
    check_file(f.c.root_dirfd, "state/knowledge", "quiesced");
    cleanup(&f);
    setup(&f);
    strcpy(f.c.transaction.paths[1].name, "update-state");
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_INVALID);
    assert(f.stops == 0);
    cleanup(&f);
    setup(&f);
    assert(!symlinkat("/tmp", f.c.root_dirfd, "state/foreign"));
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_INVALID);
    assert(f.stops == 0);
    cleanup(&f);
    setup(&f);
    f.r.expected_manifest_sha256[0] = 9;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_BUSY);
    assert(f.stops == 0);
    cleanup(&f);
    for (int fail = 0; fail <= 1; fail++) {
        setup(&f);
        executable_archive(&f, argv[0]);
        f.c.transaction.updater_probe = NULL;
        put(f.c.root_dirfd, "probe-mode", fail ? "fail" : "ready");
        assert(d2ku_install(&f.c, &f.r, &s) == (fail ? D2KU_HEALTH : D2KU_OK));
        current(&f, fail ? "releases/A" : "releases/B");
        cleanup(&f);
    }
    setup(&f);
    f.r.expected_manifest_sha256[0] = 9;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_BUSY);
    f.r.expected_manifest_sha256[0] = 1;
    put(f.c.root_dirfd, "releases/B/d2k-update", "corrupt");
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_UNTRUSTED);
    assert(f.stops == 0);
    cleanup(&f);
    setup(&f);
    assert(!fchmodat(f.c.root_dirfd, "config", 0640, 0));
    assert(!fchmodat(f.c.root_dirfd, "state", 0750, 0));
    f.failed = 1;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_HEALTH);
    struct stat modes;
    assert(!fstatat(f.c.root_dirfd, "config", &modes, 0) &&
           (modes.st_mode & 0777) == 0640);
    assert(!fstatat(f.c.root_dirfd, "state", &modes, 0) &&
           (modes.st_mode & 0777) == 0750);
    cleanup(&f);
    setup(&f);
    f.restart_candidate = 1;
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_HEALTH);
    current(&f, "releases/A");
    assert(f.now <= 242000);
    cleanup(&f);
    puts("transaction tests: PASS");
    return 0;
}
