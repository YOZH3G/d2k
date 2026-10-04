#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_update.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
int main(void) {
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
