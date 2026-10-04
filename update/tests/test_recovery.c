#include "transaction_fixture.h"
static int terminal_cut, terminal_syncs;
static d2ku_rc before_terminal_sync(void *arg, int fd) {
    fixture *f = arg;
    struct stat a, b;
    int d = openat(f->c.root_dirfd, "update-state", O_RDONLY | O_DIRECTORY);
    assert(d >= 0);
    assert(!fstat(d, &a) && !fstat(fd, &b));
    close(d);
    d2ku_journal j;
    if (a.st_ino == b.st_ino && a.st_dev == b.st_dev &&
        d2ku_journal_load(&f->c, &j) == D2KU_OK && j.phase == D2KU_COMMITTED) {
        terminal_syncs++;
        if (terminal_cut == 1)
            _exit(77);
        if (terminal_cut == 2)
            return D2KU_IO;
    }
    return fsync(fd) ? D2KU_IO : D2KU_OK;
}
static void terminal_durability(void) {
    fixture f;
    setup(&f);
    pid_t p = fork();
    assert(p >= 0);
    if (!p) {
        d2ku_status s = {0};
        terminal_cut = 1;
        f.c.sync_fd = before_terminal_sync;
        (void)d2ku_install(&f.c, &f.r, &s);
        _exit(99);
    }
    int w;
    assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && WEXITSTATUS(w) == 77);
    d2ku_journal j;
    assert(d2ku_journal_load(&f.c, &j) == D2KU_OK && j.phase == D2KU_COMMITTED);
    uint64_t seq = j.sequence;
    f.c.sync_fd = before_terminal_sync;
    terminal_cut = 2;
    terminal_syncs = 0;
    d2ku_status s = {0};
    assert(d2ku_recover(&f.c, &s) == D2KU_IO);
    assert(terminal_syncs > 0);
    terminal_cut = 0;
    terminal_syncs = 0;
    assert(d2ku_recover(&f.c, &s) == D2KU_OK && terminal_syncs > 0);
    assert(d2ku_journal_load(&f.c, &j) == D2KU_OK && j.sequence == seq);
    cleanup(&f);
}
static void relocated_snapshot(void) {
    fixture f;
    setup(&f);
    assert(!mkdirat(f.c.root_dirfd, "state/a", 0700));
    put(f.c.root_dirfd, "state/b", "x");
    pid_t p = fork();
    assert(p >= 0);
    if (!p) {
        d2ku_status s = {0};
        f.crash_phase = D2KU_SWITCHING;
        f.c.sync_fd = sync_crash;
        (void)d2ku_install(&f.c, &f.r, &s);
        _exit(99);
    }
    int w;
    assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && WEXITSTATUS(w) == 77);
    assert(!renameat(f.c.root_dirfd, "snapshots/operation-1/state/b",
                     f.c.root_dirfd, "snapshots/operation-1/state/a/b"));
    put(f.c.root_dirfd, "state/knowledge", "valid live state");
    d2ku_status s = {0};
    assert(d2ku_recover(&f.c, &s) == D2KU_RECOVERY);
    check_file(f.c.root_dirfd, "state/knowledge", "valid live state");
    cleanup(&f);
}
int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--pulse")) {
            assert(d2ku_boot_pulse(3, 0) == D2KU_OK);
            return 0;
        }
        if (!strcmp(argv[1], "--hang")) {
            for (;;)
                pause();
        }
        if (!strcmp(argv[1], "--exit"))
            return 9;
    }
    {
        fixture f;
        setup(&f);
        d2ku_status s = {0};
        char *args[] = {argv[0], "--pulse", NULL};
        assert(d2ku_supervise(&f.c, argv[0], args, &s) == D2KU_OK);
        args[1] = "--exit";
        assert(d2ku_supervise(&f.c, argv[0], args, &s) == D2KU_HEALTH);
        args[1] = "--hang";
        assert(d2ku_supervise(&f.c, argv[0], args, &s) == D2KU_HEALTH);
        cleanup(&f);
    }
    terminal_durability();
    relocated_snapshot();
    for (int phase = D2KU_PREPARED; phase <= D2KU_COMMITTED; phase++) {
        fixture f;
        setup(&f);
        pid_t p = fork();
        assert(p >= 0);
        if (!p) {
            d2ku_status s = {0};
            f.crash_phase = phase;
            f.c.sync_fd = sync_crash;
            (void)d2ku_install(&f.c, &f.r, &s);
            _exit(99);
        }
        int w;
        assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && WEXITSTATUS(w) == 77);
        d2ku_status s = {0};
        assert(d2ku_recover(&f.c, &s) == D2KU_OK);
        current(&f, phase == D2KU_COMMITTED ? "releases/B" : "releases/A");
        check_file(f.c.root_dirfd, "state/knowledge",
                   phase == D2KU_COMMITTED ? "candidate" : "original");
        assert(d2ku_recover(&f.c, &s) == D2KU_OK);
        cleanup(&f);
    }
    /* Kill the real child after every individual successful durability barrier,
     * including release preparation, current rename, and terminal publication.
     */
    {
        fixture count;
        setup(&count);
        d2ku_status s = {0};
        count.c.sync_fd = sync_crash;
        assert(d2ku_install(&count.c, &count.r, &s) == D2KU_OK);
        int total = count.sync_count;
        cleanup(&count);
        for (int point = 1; point <= total; point++) {
            fixture f;
            setup(&f);
            pid_t p = fork();
            assert(p >= 0);
            if (!p) {
                d2ku_status st = {0};
                f.crash_sync = point;
                f.c.sync_fd = sync_crash;
                (void)d2ku_install(&f.c, &f.r, &st);
                _exit(99);
            }
            int w;
            assert(waitpid(p, &w, 0) == p && WIFEXITED(w) &&
                   WEXITSTATUS(w) == 77);
            d2ku_journal j;
            int committed = d2ku_journal_load(&f.c, &j) == D2KU_OK &&
                            j.phase == D2KU_COMMITTED;
            assert(d2ku_recover(&f.c, &s) == D2KU_OK);
            current(&f, committed ? "releases/B" : "releases/A");
            check_file(f.c.root_dirfd, "state/knowledge",
                       committed ? "candidate" : "original");
            cleanup(&f);
        }
        for (int point = 1; point <= total; point++) {
            fixture f;
            setup(&f);
            f.fail_sync = point;
            f.c.sync_fd = sync_crash;
            assert(d2ku_install(&f.c, &f.r, &s) != D2KU_OK);
            f.c.sync_fd = NULL;
            assert(d2ku_recover(&f.c, &s) == D2KU_OK);
            current(&f, "releases/A");
            check_file(f.c.root_dirfd, "state/knowledge", "original");
            cleanup(&f);
        }
        printf("crash and failed-fsync barriers checked: %d\n", total);
    }
    /* An incomplete or damaged snapshot must never overwrite valid live state.
     */
    for (int complete = 0; complete <= 1; complete++) {
        fixture f;
        setup(&f);
        pid_t p = fork();
        assert(p >= 0);
        if (!p) {
            d2ku_status st = {0};
            f.crash_phase = complete ? D2KU_SWITCHING : D2KU_STOPPING;
            f.c.sync_fd = sync_crash;
            (void)d2ku_install(&f.c, &f.r, &st);
            _exit(99);
        }
        int w;
        assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && WEXITSTATUS(w) == 77);
        put(f.c.root_dirfd, "state/knowledge", "valid live state");
        if (complete)
            put(f.c.root_dirfd, "snapshots/operation-1/state/knowledge",
                "damaged");
        else
            put(f.c.root_dirfd, "snapshots/operation-1/config", "incomplete");
        d2ku_status st = {0};
        assert(d2ku_recover(&f.c, &st) == (complete ? D2KU_RECOVERY : D2KU_OK));
        check_file(f.c.root_dirfd, "state/knowledge", "valid live state");
        cleanup(&f);
    }
    for (int phase = D2KU_ROLLING_BACK; phase <= D2KU_RECOVERY_FAILED;
         phase++) {
        fixture f;
        setup(&f);
        pid_t p = fork();
        assert(p >= 0);
        if (!p) {
            d2ku_status st = {0};
            f.failed = 1;
            f.recovery_fail = phase == D2KU_RECOVERY_FAILED;
            f.crash_phase = phase;
            f.c.sync_fd = sync_crash;
            (void)d2ku_install(&f.c, &f.r, &st);
            _exit(99);
        }
        int w;
        assert(waitpid(p, &w, 0) == p && WIFEXITED(w) && WEXITSTATUS(w) == 77);
        d2ku_status st = {0};
        assert(d2ku_recover(&f.c, &st) ==
               (phase == D2KU_RECOVERY_FAILED ? D2KU_RECOVERY : D2KU_OK));
        current(&f, "releases/A");
        cleanup(&f);
    }
    fixture f;
    setup(&f);
    f.failed = 1;
    f.recovery_fail = 1;
    d2ku_status s = {0};
    assert(d2ku_install(&f.c, &f.r, &s) == D2KU_RECOVERY);
    d2ku_journal j;
    assert(d2ku_journal_load(&f.c, &j) == D2KU_OK &&
           j.phase == D2KU_RECOVERY_FAILED);
    int stops = f.stops;
    assert(d2ku_recover(&f.c, &s) == D2KU_RECOVERY);
    assert(f.stops == stops);
    cleanup(&f);
    puts("recovery tests: PASS");
    return 0;
}
