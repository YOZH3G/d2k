#include "transaction_fixture.h"
#include <signal.h>
#include <time.h>
static int mode;
static pid_t held;
static void nap(void) {
    struct timespec t = {0, 10000000};
    nanosleep(&t, NULL);
}
static int pids(int root, pid_t out[3]) {
    char b[128] = {0};
    int fd = openat(root, "offline-pids", O_RDONLY);
    if (fd < 0)
        return 0;
    ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    int a, c, d;
    if (n <= 0 || sscanf(b, "%d %d %d", &a, &c, &d) != 3)
        return 0;
    out[0] = a;
    out[1] = c;
    out[2] = d;
    return 1;
}
static void save_held(fixture *f) {
    char b[128];
    snprintf(b, sizeof b, "%d %d 0", getpid(), held);
    put(f->c.root_dirfd, "offline-pids", b);
}
static ssize_t send_hook(void *arg, int fd, const void *buf, size_t n) {
    fixture *f = arg;
    const unsigned char *b = buf;
    if (n == 8 && !memcmp(b, "D2GR", 4)) {
        held = (pid_t)(((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) |
                       ((uint32_t)b[6] << 8) | b[7]);
        save_held(f);
        if (mode == 1)
            _exit(88);
    }
    return write(fd, buf, n);
}
static int group_hook(void *arg, pid_t pid, pid_t group) {
    fixture *f = arg;
    if (mode == 2 && held == pid) {
        save_held(f);
        _exit(88);
    }
    return setpgid(pid, group);
}
static void pack(fixture *f, const char *self) {
    int fd = open(self, O_RDONLY);
    assert(fd >= 0);
    struct stat st;
    assert(!fstat(fd, &st));
    size_t bytes = (size_t)st.st_size, span = 512 + ((bytes + 511) / 512) * 512,
           total = span * 5 + 1024;
    unsigned char *tar = calloc(1, total), *data = malloc(bytes);
    assert(tar && data);
    size_t n = 0;
    while (n < bytes) {
        ssize_t z = read(fd, data + n, bytes - n);
        assert(z > 0);
        n += (size_t)z;
    }
    close(fd);
    const char *names[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg", "d2k-update"};
    f->m.file_count = 5;
    f->m.packages[0].file_count = 5;
    f->m.packages[0].size = total;
    for (size_t i = 0; i < 5; i++) {
        unsigned char *h = tar + i * span;
        strcpy((char *)h, names[i]);
        snprintf((char *)h + 100, 8, "%07o", 0755);
        snprintf((char *)h + 108, 8, "%07o", 0);
        snprintf((char *)h + 116, 8, "%07o", 0);
        snprintf((char *)h + 124, 12, "%011llo", (unsigned long long)bytes);
        snprintf((char *)h + 136, 12, "%011o", 0);
        memset(h + 148, ' ', 8);
        h[156] = '0';
        memcpy(h + 257,
               "ustar\0"
               "00",
               8);
        unsigned sum = 0;
        for (int k = 0; k < 512; k++)
            sum += h[k];
        snprintf((char *)h + 148, 7, "%06o", sum);
        h[155] = ' ';
        memcpy(h + 512, data, bytes);
        d2ku_file *file = &f->m.files[i];
        strcpy(file->path, names[i]);
        file->path_len = strlen(names[i]);
        file->size = bytes;
        file->mode = 0755;
        sha(data, bytes, file->sha256);
    }
    sha(tar, total, f->m.packages[0].sha256);
    assert(!ftruncate(f->r.archive_fd, 0));
    assert(lseek(f->r.archive_fd, 0, SEEK_SET) == 0);
    n = 0;
    while (n < total) {
        ssize_t z = write(f->r.archive_fd, tar + n, total - n);
        assert(z > 0);
        n += (size_t)z;
    }
    free(data);
    free(tar);
}
int main(int argc, char **argv) {
    (void)sync_crash;
    (void)current;
    if (argc == 2 && !strcmp(argv[1], "--release-id")) {
        puts("B");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--self-check")) {
        pid_t grand = fork();
        assert(grand >= 0);
        if (!grand)
            for (;;)
                pause();
        char b[128];
        snprintf(b, sizeof b, "%d %d %d", getppid(), getpid(), grand);
        put(AT_FDCWD, "../../offline-pids", b);
        for (;;)
            pause();
    }
    if (argc == 4 && !strcmp(argv[1], "--worker")) {
        fixture f;
        setup(&f);
        int root = open(argv[2], O_RDONLY | O_DIRECTORY),
            archive = openat(root, "archive", O_RDWR);
        assert(root >= 0 && archive >= 0);
        cleanup(&f);
        f.c.root_dirfd = root;
        f.r.archive_fd = archive;
        pack(&f, argv[0]);
        f.c.boot_control_fd = 5;
        f.c.transaction.offline = NULL;
        f.c.write_fd = send_hook;
        f.c.transaction.process_group = group_hook;
        mode = atoi(argv[3]);
        assert(d2ku_boot_pulse(3, 0) == D2KU_OK);
        d2ku_status s = {0};
        (void)d2ku_install(&f.c, &f.r, &s);
        return 6;
    }
    for (int test = 0; test < 3; test++) {
        fixture f;
        setup(&f);
        pid_t service_pid = fork();
        assert(service_pid >= 0);
        if (!service_pid) {
            setpgid(0, 0);
            for (;;)
                pause();
        }
        setpgid(service_pid, service_pid);
        pid_t killer = -1;
        if (!test) {
            killer = fork();
            assert(killer >= 0);
            if (!killer) {
                pid_t ids[3];
                for (int n = 0; n < 500; n++) {
                    if (pids(f.c.root_dirfd, ids) && ids[2] > 0) {
                        kill(ids[0], SIGKILL);
                        _exit(0);
                    }
                    nap();
                }
                _exit(90);
            }
        }
        char mode_text[8];
        snprintf(mode_text, sizeof mode_text, "%d", test);
        char *args[] = {argv[0], "--worker", f.path, mode_text, NULL};
        d2ku_status s = {0};
        assert(d2ku_supervise(&f.c, argv[0], args, &s) == D2KU_HEALTH);
        if (killer > 0) {
            /* Супервизор — subreaper и собирает всех завершившихся потомков,
             * в том числе этого соседа: его уже могли reap-нуть за нас. */
            int w;
            pid_t got = waitpid(killer, &w, 0);
            assert(got == killer ? WIFEXITED(w) && !WEXITSTATUS(w)
                                 : errno == ECHILD);
        }
        pid_t ids[3] = {0};
        assert(pids(f.c.root_dirfd, ids));
        int gone = 1;
        for (int i = 1; i < 3; i++)
            if (ids[i] > 0 && !(kill(ids[i], 0) < 0 && errno == ESRCH))
                gone = 0;
        int service_alive = kill(service_pid, 0) == 0;
        kill(-service_pid, SIGKILL);
        assert(waitpid(service_pid, NULL, 0) == service_pid);
        if (!gone) {
            if (ids[1] > 0)
                kill(-ids[1], SIGKILL);
            if (ids[2] > 0)
                kill(ids[2], SIGKILL);
        }
        assert(gone && service_alive);
        check_file(f.c.root_dirfd, "state/knowledge", "original");
        cleanup(&f);
    }
    puts("offline process ownership crash windows: PASS");
    return 0;
}
