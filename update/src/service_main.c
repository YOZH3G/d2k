#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "lifecycle.h"
#include "transaction_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <signal.h>
#include <sys/prctl.h>
#endif
static d2ku_rc enabled(d2ku_ctx *c, uint64_t mask) {
  int d = openat(c->root_dirfd, "update-state",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (d < 0)
    return D2KU_IO;
  char tmp[64];
  snprintf(tmp, sizeof tmp, ".enabled-%ld", (long)getpid());
  int f = openat(d, tmp, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY | O_CLOEXEC,
                 0600);
  d2ku_rc r = D2KU_IO;
  if (f >= 0) {
    char b[24];
    int n = snprintf(b, sizeof b, "%llu\n", (unsigned long long)mask);
    if (write(f, b, (size_t)n) == n && !fsync(f) &&
        !renameat(d, tmp, d, "enabled") && !fsync(d))
      r = D2KU_OK;
    close(f);
    unlinkat(d, tmp, 0);
  }
  close(d);
  return r;
}
int main(int argc, char **argv) {
#ifdef __linux__
  pid_t caller = getppid();
  if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != caller)
    return 1;
#endif
  const char *root = "/opt/d2k";
  int at = 1, internal = 0, validate = 0;
  if (at + 1 < argc && !strcmp(argv[at], "--root")) {
    root = argv[at + 1];
    at += 2;
  }
  if (at + 1 < argc && (!strcmp(argv[at], "--maintenance-fd") ||
                        !strcmp(argv[at], "--validate-maintenance-fd"))) {
    validate = !strcmp(argv[at], "--validate-maintenance-fd");
    if (strcmp(argv[at + 1], "4"))
      return 2;
    internal = 1;
    at += 2;
  }
  d2ku_ctx c = {0};
  c.maintenance_lock_fd = -1;
  c.health_runtime_dirfd = -1;
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  struct stat st;
  if (c.root_dirfd < 0 || fstat(c.root_dirfd, &st) || st.st_uid != geteuid() ||
      (st.st_mode & 022))
    return 1;
  if (internal) {
    c.maintenance_lock_fd = 4;
    if (d2ku_service_lock_valid(&c, 4) != D2KU_OK)
      return 1;
  }
  if (validate)
    return at == argc ? 0 : 2;
  if (at >= argc)
    return 2;
  if (!strcmp(argv[at], "--launch")) {
    if (internal || at + 1 >= argc)
      return 2;
    const char *bin = argv[at + 1];
    const char *mode = at + 2 < argc ? argv[at + 2] : "";
    int offline =
        at + 3 == argc &&
        (!strcmp(mode, "--version") || !strcmp(mode, "--help") ||
         !strcmp(mode, "--release-id") || !strcmp(mode, "--self-check"));
    int tg_readonly =
        !strcmp(bin, "d2ktg") &&
        ((at + 4 == argc && !strcmp(mode, "--check-config")) ||
         (at + 6 == argc && !strcmp(mode, "--check-instagram-ip")));
    if (!offline && !tg_readonly) {
      fprintf(stderr,
              "managed daemons must be started through d2k service commands\n");
      return 2;
    }

    if (strcmp(bin, "d2kd") && strcmp(bin, "d2kc") && strcmp(bin, "d2kpanel") &&
        strcmp(bin, "d2ktg"))
      return 2;
    d2ku_rc lr;
    do {
      lr = d2ku_maintenance_lock(&c, &c.maintenance_lock_fd);
      if (lr == D2KU_BUSY) {
        struct timespec t = {0, 100000000};
        nanosleep(&t, NULL);
      }
    } while (lr == D2KU_BUSY);
    if (lr != D2KU_OK)
      return 1;
    char id[D2KU_ID_MAX + 1], path[1200], asset[1200];
    if (d2ku_tx_current(&c, id) != D2KU_OK)
      return 1;
    snprintf(path, sizeof path, "%s/releases/%s/%s", root, id, bin);
    snprintf(asset, sizeof asset, "%s/releases/%s/files/fake", root, id);
    setenv("D2K_FAKE_DIR", asset, 1);
    snprintf(asset, sizeof asset, "%s/releases/%s/files/tg-roots.pem", root,
             id);
    setenv("D2K_TG_CA_BUNDLE", asset, 1);
    close(c.maintenance_lock_fd);
    close(c.root_dirfd);
    close(3);
    close(4);
    close(5);
    argv[at + 1] = path;
    execv(path, &argv[at + 1]);
    return 1;
  }
  const char *action = argv[at++], *release = "-";
  uint64_t mask = 0;
  d2ku_service_config sc;
  d2ku_rc r = d2ku_service_configure(&c, root, &sc);
  if (r != D2KU_OK) {
    fprintf(stderr,
            "unsupported managed configuration (personal writable paths must "
            "be inside installation root), result=%d\n",
            r);
    return 1;
  }
  uint64_t configured_mask = sc.enabled;
  if (internal) {
    if (at + 2 != argc)
      return 2;
    release = argv[at++];
    char *end;
    mask = strtoull(argv[at], &end, 10);
    if (!*argv[at] || *end || mask > 15)
      return 2;
  } else {
    if (!strcmp(action, "service")) {
      if (at >= argc)
        return 2;
      action = argv[at++];
    }
    if (!strcmp(action, "check") || !strcmp(action, "install")) {
      d2ku_command command = {.op = D2KU_CMD_CHECK, .force = 1};
      if (!strcmp(action, "install")) {
        if (at + 2 != argc) {
          fprintf(stderr, "not installed: use d2k-update check, status, then "
                          "service install RELEASE_ID MANIFEST_SHA256\n");
          return 2;
        }
        char json[512];
        snprintf(json, sizeof json,
                 "{\"release_id\":\"%s\",\"manifest_sha256\":\"%s\"}", argv[at],
                 argv[at + 1]);
        if (d2ku_command_parse(D2KU_CMD_INSTALL, json, &command))
          return 2;
      } else if (at != argc)
        return 2;
      char socket_path[1200];
      snprintf(socket_path, sizeof socket_path, "%s/update-state/updater.sock",
               root);
      int fd = d2ku_ipc_connect(socket_path);
      if (fd < 0) {
        fprintf(stderr, "update daemon unavailable; not installed\n");
        return 3;
      }
      char *json = malloc(D2KU_IPC_MAX);
      int code = 503;
      int error =
          json ? d2ku_ipc_exchange(fd, &command, &code, json, D2KU_IPC_MAX)
               : -1;
      close(fd);
      if (!error)
        puts(json);
      free(json);
      return error ? 3 : code == 200 || code == 202 ? 0 : code == 409 ? 4 : 1;
    }
    if (at != argc)
      return 2;
    r = d2ku_service_recovery_context(&c, sc.runtime);
    if (r != D2KU_OK)
      return 1;
    do {
      r = d2ku_maintenance_lock(&c, &c.maintenance_lock_fd);
      if (r == D2KU_BUSY) {
        struct timespec t = {0, 100000000};
        nanosleep(&t, NULL);
      }
    } while (r == D2KU_BUSY);
    if (r != D2KU_OK)
      return 1;
    r = d2ku_service_configure(&c, root, &sc);
    if (r != D2KU_OK)
      goto done;
    configured_mask = sc.enabled;
    if (c.health_runtime_dirfd >= 0)
      close(c.health_runtime_dirfd);
    c.health_runtime_dirfd = -1;
    r = d2ku_service_recovery_context(&c, sc.runtime);
    if (r != D2KU_OK)
      goto done;
    d2ku_lifecycle lifecycle;
    d2ku_rc lr = d2ku_lifecycle_load(&c, &lifecycle);
    if (strcmp(action, "uninstall") && lr != D2KU_ABSENT) {
      r = D2KU_BUSY;
      goto done;
    }
    if (!strcmp(action, "uninstall")) {
      r = d2ku_lifecycle_quiesce(&c, root);
      if (r != D2KU_OK)
        goto done;
    }
    d2ku_status status = {0};
    if (!fstatat(c.root_dirfd, "update-state/bootstrap.pending", &st,
                 AT_SYMLINK_NOFOLLOW)) {
      close(c.maintenance_lock_fd);
      c.maintenance_lock_fd = -1;
      char prefix[1024];
      if (strlen(root) >= sizeof prefix)
        return 1;
      strcpy(prefix, root);
      char *slash = strrchr(prefix, '/');
      if (!slash || slash == prefix)
        return 1;
      *slash = 0;
      c.bootstrap_prefix_fd =
          open(prefix, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      c.bootstrap_bundle_fd = -1;
      r = d2ku_bootstrap(&c, &status);
      close(c.bootstrap_prefix_fd);
      if (r != D2KU_OK)
        return 1;
      do {
        r = d2ku_maintenance_lock(&c, &c.maintenance_lock_fd);
        if (r == D2KU_BUSY) {
          struct timespec t = {0, 100000000};
          nanosleep(&t, NULL);
        }
      } while (r == D2KU_BUSY);
      if (r != D2KU_OK)
        return 1;
    }
    r = d2ku_tx_recover_locked(&c, &status);
    if (r != D2KU_OK)
      goto done;
    r = d2ku_service_capture(&sc, &mask);
    if (r != D2KU_OK)
      goto done;
    if (!strcmp(action, "start"))
      mask = configured_mask;
    if (!strcmp(action, "boot-start"))
      action = "start";
    if (!strcmp(action, "engine-start") || !strcmp(action, "engine-restart"))
      mask |= 3;
    if (!strcmp(action, "engine-stop"))
      mask &= ~UINT64_C(3);
    if (!strcmp(action, "telegram-enable"))
      mask |= 8;
    if (!strcmp(action, "telegram-disable"))
      mask &= ~UINT64_C(8);
  }
  /* Persist service intent before start/stop so a crash/reboot preserves an
   * administratively disabled service. Transaction start writes saved mask. */
  if (!strcmp(action, "start") || !strcmp(action, "engine-start") ||
      !strcmp(action, "engine-restart") || !strcmp(action, "engine-stop") ||
      !strcmp(action, "telegram-enable") ||
      !strcmp(action, "telegram-disable")) {
    r = enabled(&c, mask);
    if (r != D2KU_OK)
      goto done;
  }
  r = internal ? d2ku_service_dispatch(&sc, action, release, mask)
               : d2ku_service_call(&sc, action, release, mask);
  if (r == D2KU_OK && !internal && !strcmp(action, "stop"))
    r = enabled(&c, 0);
done:
  if (!internal)
    close(c.maintenance_lock_fd);
  if (c.health_runtime_dirfd >= 0)
    close(c.health_runtime_dirfd);
  close(c.root_dirfd);
  if (r != D2KU_OK)
    fprintf(stderr, "managed lifecycle result=%d\n", r);
  return r == D2KU_OK ? 0 : 1;
}
