#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../src/legacy_runtime.h"
#include "d2k_update.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
static void legacy_arguments(void) {
  d2ku_ctx ctx = {0};
  d2ku_service_config s = {.ctx = &ctx};
  strcpy(s.root, "/opt/d2k");
  strcpy(s.runtime, "/tmp/d2k");
  strcpy(s.state, "/opt/d2k/state");
  strcpy(s.legacy_mode, "observe");
  strcpy(s.legacy_listen, "127.0.0.1:8090");
  strcpy(s.legacy_mark, "0x2d");
  strcpy(s.legacy_probe_mark, "0x2e");
  strcpy(s.legacy_measure_mark, "0x2f");
  strcpy(s.legacy_flows, "2048");
  ctx.health_queue = 2000;
  strcpy(ctx.health_state_paths[2], "state/telegram.status");
  const char *dp[] = {"d2kd",
                      "--queue",
                      "2000",
                      "--control",
                      "/opt/d2k/run/d2kd.sock",
                      "--log",
                      "/opt/d2k/log/d2kd.log",
                      "--mark",
                      "45",
                      "--probe-mark",
                      "46",
                      "--udp-reverse-hook"};
  const char *core[] = {"d2kc",
                        "--control",
                        "/opt/d2k/run/d2kd.sock",
                        "--catalog",
                        "/opt/d2k/state/catalog.json",
                        "--live",
                        "/tmp/d2k/live.json",
                        "--log",
                        "/opt/d2k/log/d2kc.log",
                        "--mark",
                        "46",
                        "--measure-mark",
                        "47"};
  const char *panel[] = {"d2kpanel", "serve",
                         "--live",   "/tmp/d2k/live.json",
                         "--log",    "/opt/d2k/log/panel.log"};
  const char *tg[] = {"d2ktg", "--log", "/opt/d2k/log/telegram.log"};
  const char *const *roles[] = {dp, core, panel, tg};
  size_t counts[] = {sizeof dp / sizeof *dp, sizeof core / sizeof *core,
                     sizeof panel / sizeof *panel, sizeof tg / sizeof *tg};
  for (unsigned role = 0; role < 4; role++) {
    const char *args[64];
    size_t n = counts[role];
    memcpy(args, roles[role], n * sizeof *args);
    assert(d2ku_legacy_argv(&s, role, n, args)); /* Real omitted defaults. */
    args[n] = "--unknown";
    args[n + 1] = "value";
    assert(!d2ku_legacy_argv(&s, role, n + 2, args));
    args[n] = "--health-file";
    args[n + 1] = "/tmp/health";
    assert(!d2ku_legacy_argv(&s, role, n + 2, args));
    args[n] = "--log";
    args[n + 1] = "/opt/d2k/log/panel.log";
    assert(!d2ku_legacy_argv(&s, role, n + 2,
                             args)); /* Duplicates are ambiguous. */
    assert(!d2ku_legacy_argv(&s, role, n + 1, args)); /* Missing value. */
  }
  const char *args[64];
  size_t n = counts[0];
  memcpy(args, dp, n * sizeof *args);
  const char *extra[] = {"--flows",      "2048", "--queue-len",   "1024",
                         "--copy-range", "1600", "--sched-slots", "128",
                         "--journal",    "256",  "--idle",        "120",
                         "--duration",   "0",    "--stats",       "60"};
  memcpy(args + n, extra, sizeof extra);
  n += sizeof extra / sizeof *extra;
  assert(d2ku_legacy_argv(&s, 0, n, args));
  args[n - 1] = "-1";
  assert(!d2ku_legacy_argv(&s, 0, n, args));
  args[n - 1] = "4294967296";
  assert(!d2ku_legacy_argv(&s, 0, n, args));
  args[n - 1] = "60";
  args[counts[0] + 1] = "2049";
  assert(!d2ku_legacy_argv(&s, 0, n, args));
  n = counts[1];
  memcpy(args, core, n * sizeof *args);
  args[n] = "--https-cache";
  args[n + 1] = "/opt/d2k/state/https-cache.txt";
  assert(d2ku_legacy_argv(&s, 1, n + 2, args));
  args[n + 1] = "/outside/cache";
  assert(!d2ku_legacy_argv(&s, 1, n + 2, args));
  n = counts[2];
  memcpy(args, panel, n * sizeof *args);
  const char *paths[] = {
      "--state-dir",    "--assets",          "--service",
      "--config",       "--engine-pid",      "--controller-pid",
      "--telegram-pid", "--telegram-status", "--listen"};
  for (size_t i = 0; i < sizeof paths / sizeof *paths; i++) {
    args[n] = paths[i];
    args[n + 1] = "/outside/resource";
    assert(!d2ku_legacy_argv(&s, 2, n + 2, args));
  }
  /* Historical panel does not read TG_STATUS from config. Its S99 launch
   * keeps the fixed root/state default even when TG uses a custom status. */
  strcpy(ctx.health_state_paths[2], "personal/tg.status");
  assert(d2ku_legacy_argv(&s, 2, n, args));
  args[n] = "--telegram-status";
  args[n + 1] = "/opt/d2k/personal/tg.status";
  assert(!d2ku_legacy_argv(&s, 2, n + 2, args));
  strcpy(ctx.health_state_paths[2], "state/telegram.status");
  strcpy(s.legacy_mode, "apply");
  assert(!d2ku_legacy_argv(
      &s, 2, n, args)); /* No MODE: historical panel defaults observe. */
  args[n] = "--mode";
  args[n + 1] = "apply";
  assert(d2ku_legacy_argv(&s, 2, n + 2, args));
  strcpy(s.legacy_mode, "observe");
  args[n] = "--queue";
  args[n + 1] = "2001";
  assert(!d2ku_legacy_argv(&s, 2, n + 2, args));
  args[n] = "--mode";
  args[n + 1] = "apply";
  assert(!d2ku_legacy_argv(&s, 2, n + 2, args));
  puts("historical complete role argv/defaults/resource contract: PASS");
}
int main(void) {
  legacy_arguments();
  char root[] = "/tmp/d2ku-service.XXXXXX";
  assert(mkdtemp(root));
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  c.maintenance_lock_fd = -1;
  int fd = -1;
  assert(d2ku_maintenance_lock(&c, &fd) == D2KU_OK);
  assert(d2ku_service_lock_valid(&c, fd) == D2KU_OK);
  int fake = openat(c.root_dirfd, "fake", O_CREAT | O_RDWR, 0600);
  assert(fake >= 0);
  assert(flock(fake, LOCK_EX | LOCK_NB) == 0);
  assert(d2ku_service_lock_valid(&c, fake) != D2KU_OK);
  close(fake);
  close(fd);
  fd = openat(c.root_dirfd, "update-state/maintenance.lock", O_RDWR);
  assert(d2ku_service_lock_valid(&c, fd) != D2KU_OK);
  close(fd);
  char cfg[2048];
  snprintf(cfg, sizeof cfg,
           "MODE=off\nTG_ENABLED=0\nSTATE_DIR=%s/knowledge\nTG_IDENTITY=%s/"
           "personal/identity\nD2K_RUNTIME_DIR=%s/"
           "volatile\nPANEL_LISTEN=192.0.2.1:8181\nQUEUE_NUM=2314\n",
           root, root, root);
  fd = openat(c.root_dirfd, "config", O_CREAT | O_WRONLY, 0600);
  assert(write(fd, cfg, strlen(cfg)) == (ssize_t)strlen(cfg));
  close(fd);
  d2ku_service_config sc;
  assert(d2ku_service_configure(&c, root, &sc) == D2KU_OK);
  assert(c.wire_version == 13 && c.health_panel_port == 8181 &&
         c.health_queue == 2314);
  assert(!strcmp(c.transaction.paths[0].name, "config"));
  assert(
      c.transaction.path_count ==
      4); /* config, actual catalog state, configured panel state, personal */
  assert(!strcmp(sc.panel_host, "192.0.2.1"));
  fd = openat(c.root_dirfd, "config", O_TRUNC | O_WRONLY);
  assert(write(fd, "STATE_DIR=/outside\n", 19) == 19);
  close(fd);
  assert(d2ku_service_configure(&c, root, &sc) == D2KU_INCOMPATIBLE);
  close(c.root_dirfd);
  char cmd[512];
  snprintf(cmd, sizeof cmd, "rm -rf %s", root);
  assert(system(cmd) == 0);
  puts("service lock ownership and configuration inventory: PASS");
  return 0;
}
