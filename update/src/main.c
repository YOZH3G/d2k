#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "daemon.h"
#include "lifecycle.h"
#include "startup.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#ifndef D2K_RELEASE_ID
#define D2K_RELEASE_ID "dev"
#endif
#ifndef D2KU_BUILD_TIMESTAMP
#define D2KU_BUILD_TIMESTAMP 0
#endif
static _Atomic int interrupted;
static void on_signal(int n) {
  (void)n;
  interrupted = 1;
}
static void pause_ms(unsigned ms) {
  struct timespec t = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000};
  nanosleep(&t, NULL);
}
static void *heartbeat(void *p) {
  int fd = *(int *)p;
  while (!interrupted) {
    if (d2ku_boot_pulse(fd, 0) != D2KU_OK) {
      interrupted = 1;
      break;
    }
    pause_ms(1000);
  }
  return NULL;
}
static void *worker(void *p) {
  d2ku_daemon *d = p;
  while (!interrupted) {
    d2ku_daemon_work(d);
    pause_ms(50);
  }
  return NULL;
}
static void progress(void *arg, uint64_t bytes) {
  d2ku_daemon *d = arg;
  pthread_mutex_lock(&d->mutex);
  d->status.received_bytes = bytes;
  pthread_mutex_unlock(&d->mutex);
}
static int root_path(int fd, char path[1024]) {
#ifdef __linux__
  char proc[64];
  snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
  ssize_t n = readlink(proc, path, 1023);
  if (n < 0)
    return -1;
  path[n] = 0;
  return 0;
#else
  return fcntl(fd, F_GETPATH, path);
#endif
}
static int serve(d2ku_daemon *d, int pulse, int probe, int lock, int guard) {
  d2ku_ctx *c = d->ctx;
  int socket_fd = -1;
  char path[1200];
  pthread_t beat, work;
  int hasbeat = 0, haswork = 0;
  if (!probe) {
    struct stat st;
    snprintf(path, sizeof path, "%s/update-state/updater.sock", d->root);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof address.sun_path) {
      goto failed;
    }
    strcpy(address.sun_path, path);
    if (lstat(path, &st) == 0 &&
        (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid())) {
      goto failed;
    }
    unlink(path);
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
      goto failed;
    }
    fcntl(socket_fd, F_SETFD, FD_CLOEXEC);
    fcntl(socket_fd, F_SETFL, O_NONBLOCK);
    mode_t old = umask(077);
    int r = bind(socket_fd, (struct sockaddr *)&address, sizeof address);
    umask(old);
    if (r || chmod(path, 0600) || listen(socket_fd, 16)) {
      close(socket_fd);
      goto failed;
    }
  }
  d2ku_maintenance_unlock(guard);
  guard = -1;
  if (pulse >= 0) {
    if (d2ku_boot_pulse(pulse, 1) != D2KU_OK)
      goto failed;
    if (pthread_create(&beat, NULL, heartbeat, &pulse))
      goto failed;
    hasbeat = 1;
  }
  if (!probe) {
    if (pthread_create(&work, NULL, worker, d))
      goto failed;
    haswork = 1;
  }
  while (!interrupted) {
    if (probe) {
      pause_ms(100);
      continue;
    }
    pthread_mutex_lock(&d->mutex);
    int handoff = d->handoff || d->stop;
    pthread_mutex_unlock(&d->mutex);
    if (handoff)
      break;
    struct pollfd f = {socket_fd, POLLIN, 0};
    int r = poll(&f, 1, 100);
    if (r < 0 && errno != EINTR)
      break;
    if (r > 0) {
      int client = accept(socket_fd, NULL, NULL);
      if (client >= 0) {
        fcntl(client, F_SETFD, FD_CLOEXEC);
        d2ku_command cmd;
        int received_lock = -1;
        if (!d2ku_ipc_peer(client, geteuid()) &&
            !d2ku_ipc_receive_lock(client, &cmd, &received_lock)) {
          if (cmd.op == D2KU_CMD_QUIESCE) {
            pthread_mutex_lock(&d->mutex);
            int code = 409;
            if (!d->status.busy && !d->stop && received_lock >= 0 &&
                d2ku_service_lock_valid(c, received_lock) == D2KU_OK) {
              d->stop = 1;
              c->maintenance_lock_fd = received_lock;
              char op[65];
              struct timespec ts;
              clock_gettime(CLOCK_MONOTONIC, &ts);
              snprintf(op, sizeof op, "uninstall-%ld-%lld", (long)getpid(),
                       (long long)ts.tv_sec);
              if (d2ku_lifecycle_intent(c, op, getpid()) == D2KU_OK)
                code = 202;
              c->maintenance_lock_fd = -1;
            }
            pthread_mutex_unlock(&d->mutex);
            d2ku_ipc_reply(client, code, "{\"state\":\"quiescing\"}");
          } else {
            d2ku_request req = {
                .command = cmd.op, .force = cmd.force, .enabled = cmd.enabled};
            strcpy(req.release_id, cmd.release_id);
            strcpy(req.transaction_id, cmd.operation_id);
            memcpy(req.manifest_sha256, cmd.hash, 32);
            d2ku_status s;
            d2ku_rc rc = d2ku_dispatch(c, &req, &s);
            char *json = malloc(D2KU_IPC_MAX);
            if (json) {
              if (d2ku_daemon_json_status(d, &s, json, D2KU_IPC_MAX) != D2KU_OK)
                strcpy(json, "{\"state\":\"unavailable\"}");
              int code = rc == D2KU_BUSY                        ? 409
                         : rc == D2KU_INVALID                   ? 400
                         : rc != D2KU_OK                        ? 503
                         : cmd.op == D2KU_CMD_STATUS || !s.busy ? 200
                                                                : 202;
              d2ku_ipc_reply(client, code, json);
              free(json);
            }
          }
        }
        if (received_lock >= 0)
          close(received_lock);
        close(client);
      }
    }
    d2ku_daemon_tick(d);
  }
  interrupted = 1;
  if (haswork)
    pthread_join(work, NULL);
  if (hasbeat)
    pthread_join(beat, NULL);
  if (socket_fd >= 0) {
    close(socket_fd);
    unlink(path);
  }
  if (d->stop && c->boot_control_fd <= 2)
    (void)d2ku_lifecycle_ack(c, getpid());
  if (lock >= 0)
    close(lock);
  return d->stop ? 76 : d->handoff ? 75 : 0;
failed:
  d2ku_maintenance_unlock(guard);
  interrupted = 1;
  if (haswork)
    pthread_join(work, NULL);
  if (hasbeat)
    pthread_join(beat, NULL);
  if (socket_fd >= 0) {
    close(socket_fd);
    unlink(path);
  }
  if (lock >= 0)
    close(lock);
  return 1;
}
static int client(const char *root, int argc, char **argv) {
  d2ku_command_op op = !strcmp(argv[0], "status")     ? D2KU_CMD_STATUS
                       : !strcmp(argv[0], "check")    ? D2KU_CMD_CHECK
                       : !strcmp(argv[0], "install")  ? D2KU_CMD_INSTALL
                       : !strcmp(argv[0], "rollback") ? D2KU_CMD_ROLLBACK
                       : !strcmp(argv[0], "settings") ? D2KU_CMD_SETTINGS
                                                      : 0;
  if (!op)
    return 2;
  const char *operation = NULL;
  if (argc >= 3 && !strcmp(argv[argc - 2], "--operation-id")) {
    operation = argv[argc - 1];
    argc -= 2;
  }
  char json[512] = "{}";
  if (op == D2KU_CMD_CHECK) {
    if (argc == 2 && !strcmp(argv[1], "--force"))
      strcpy(json, "{\"force\":true}");
    else if (argc != 1)
      return 2;
  } else if (op == D2KU_CMD_INSTALL || op == D2KU_CMD_ROLLBACK) {
    if (argc != 3)
      return 2;
    snprintf(json, sizeof json,
             "{\"release_id\":\"%s\",\"manifest_sha256\":\"%s\"}", argv[1],
             argv[2]);
  } else if (op == D2KU_CMD_SETTINGS) {
    if (argc != 2 || (strcmp(argv[1], "on") && strcmp(argv[1], "off")))
      return 2;
    snprintf(json, sizeof json, "{\"enabled\":%s}",
             !strcmp(argv[1], "on") ? "true" : "false");
  } else if (argc != 1)
    return 2;
  if (operation) {
    size_t n = strlen(json);
    if (n + strlen(operation) + 24 >= sizeof json)
      return 2;
    snprintf(json + n - 1, sizeof json - n + 1, "%s\"operation_id\":\"%s\"}",
             n > 2 ? "," : "", operation);
  }
  d2ku_command cmd;
  if (d2ku_command_parse(op, json, &cmd))
    return 2;
  char path[1200];
  snprintf(path, sizeof path, "%s/update-state/updater.sock", root);
  int fd = d2ku_ipc_connect(path);
  if (fd < 0) {
    puts("{\"state\":\"unavailable\"}");
    return 3;
  }
  char *out = malloc(D2KU_IPC_MAX);
  int code;
  int r = out ? d2ku_ipc_exchange(fd, &cmd, &code, out, D2KU_IPC_MAX) : -1;
  close(fd);
  if (!r)
    puts(out);
  free(out);
  return r ? 3 : code == 200 || code == 202 ? 0 : code == 409 ? 4 : 1;
}
int main(int argc, char **argv) {
  if (argc == 2) {
    if (!strcmp(argv[1], "--release-id")) {
      puts(D2K_RELEASE_ID);
      return 0;
    }
    if (!strcmp(argv[1], "--boot-protocol")) {
      puts("1");
      return 0;
    }
    if (!strcmp(argv[1], "--self-check"))
      return 0;
  }
  const char *root = "/opt/d2k", *fixture = NULL;
  int at = 1, pulse = -1, probe = 0, rootfd = -1;
  if (at + 1 < argc && !strcmp(argv[at], "--root")) {
    root = argv[at + 1];
    at += 2;
  }
  if (at + 1 < argc && !strcmp(argv[at], "--fixture-config")) {
    fixture = argv[at + 1];
    at += 2;
  }
  if (at >= argc)
    return 2;
  if (!strcmp(argv[at], "service")) {
    if (fixture || at + 1 >= argc)
      return 2;
    char path[1200];
    snprintf(path, sizeof path, "%s/boot/d2k-service-adapter", root);
    if (!strcmp(argv[at + 1], "install")) {
      if (at + 4 != argc)
        return 2;
      close(3);
      close(4);
      close(5);
      execl(path, path, "--root", root, "service", "install", argv[at + 2],
            argv[at + 3], (char *)NULL);
    } else {
      if (at + 2 != argc)
        return 2;
      close(3);
      close(4);
      close(5);
      execl(path, path, "--root", root, "service", argv[at + 1], (char *)NULL);
    }
    return 3;
  }
  if (!strcmp(argv[at], "--boot-worker") || !strcmp(argv[at], "--boot-probe")) {
    probe = !strcmp(argv[at], "--boot-probe");
    if (fixture || at + 1 >= argc || strcmp(argv[at + 1], "3"))
      return 2;
    pulse = 3;
    at += 2;
    if (probe) {
      if (at + 2 != argc || strcmp(argv[at], "--root-fd") ||
          strcmp(argv[at + 1], "4"))
        return 2;
      rootfd = fcntl(4, F_DUPFD_CLOEXEC, 10);
      at += 2;
    }
    if (at != argc)
      return 2;
  } else if (strcmp(argv[at], "serve"))
    return fixture ? 2 : client(root, argc - at, argv + at);
  else if (at + 1 != argc)
    return 2;
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  if (pulse >= 0) {
    fcntl(3, F_SETFD, FD_CLOEXEC);
    fcntl(5, F_SETFD, FD_CLOEXEC);
  }
  d2ku_ctx c = {.root_dirfd = -1,
                .health_runtime_dirfd = -1,
                .maintenance_lock_fd = -1,
                .updater_version = 1,
                .wire_version = 13,
                .state_version = 1,
                .boot_control_fd = pulse >= 0 && !probe ? 5 : -1};
  char rootbuf[1024];
  if (rootfd >= 0) {
    if (root_path(rootfd, rootbuf))
      return 1;
    root = rootbuf;
    c.root_dirfd = rootfd;
  } else
    c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (c.root_dirfd < 0 || fstat(c.root_dirfd, &st) || st.st_uid != geteuid() ||
      (st.st_mode & 022))
    return 1;
  d2ku_lifecycle lifecycle;
  if (d2ku_lifecycle_load(&c, &lifecycle) != D2KU_ABSENT) {
    fprintf(stderr, "updater unavailable: installation quiescing\n");
    close(c.root_dirfd);
    return 3;
  }
  if (!probe)
    d2ku_startup_barrier("daemon");
  d2ku_daemon config = {.ctx = &c};
  d2ku_rc rc = d2ku_daemon_config(&config, fixture);
  if (rc != D2KU_OK) {
    fprintf(stderr, "updater unavailable: bootstrap configuration result=%d\n",
            rc);
    close(c.root_dirfd);
    return 3;
  }
  if (c.clock.build_timestamp < D2KU_BUILD_TIMESTAMP)
    c.clock.build_timestamp = D2KU_BUILD_TIMESTAMP;
  char feed[2048];
  strcpy(feed, config.feed);
  int startup_guard = -1, ownership = -1;
  if (!probe) {
    rc = d2ku_startup_claim(&c, "daemon.lock", &startup_guard, &ownership);
    if (rc != D2KU_OK) {
      fprintf(stderr, "updater unavailable: startup ownership result=%d\n", rc);
      close(c.root_dirfd);
      return 3;
    }
  }
  d2ku_daemon d;
  rc = d2ku_daemon_open(&d, &c, probe);
  if (rc != D2KU_OK) {
    d2ku_maintenance_unlock(startup_guard);
    if (ownership >= 0)
      close(ownership);
    close(c.root_dirfd);
    return 1;
  }
  snprintf(d.root, sizeof d.root, "%s", root);
  strcpy(d.feed, feed);
  if (probe) {
    rc = d2ku_service_configure(&c, root, &d.services);
    if (rc == D2KU_OK) {
      c.health_runtime_dirfd = open(
          d.services.runtime, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
      if (c.health_runtime_dirfd < 0 || fstat(c.health_runtime_dirfd, &st) ||
          st.st_uid != geteuid() || (st.st_mode & 077))
        rc = D2KU_INVALID;
    }
    if (rc == D2KU_OK)
      rc = d2ku_platform_clock(&c.clock);
  } else {
    rc = d2ku_daemon_refresh(&d);
  }
  c.refresh = d2ku_daemon_refresh;
  c.refresh_arg = &d;
  c.progress = progress;
  c.progress_arg = &d;
  int result = 1;
  if (rc == D2KU_OK)
    result = serve(&d, pulse, probe, ownership, startup_guard);
  else {
    d2ku_maintenance_unlock(startup_guard);
    if (ownership >= 0)
      close(ownership);
  }
  d2ku_daemon_destroy(&d);
  if (c.health_runtime_dirfd >= 0)
    close(c.health_runtime_dirfd);
  close(c.root_dirfd);
  return result;
}
