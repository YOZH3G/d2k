#include "transaction_fixture.h" /* Supplies feature macros before libc. */

#include "../src/daemon.h"
int main(void) {
  fixture f;
  setup(&f);
  f.c.sync_fd = sync_crash;
  d2ku_daemon d;
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  d.selected = 1;
  d.index = f.i;
  *d.manifest = f.m;
  f.r.command = D2KU_CMD_INSTALL;
  d2ku_status status;
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK && status.busy);
  assert(d2ku_install(&f.c, &f.r, &status) == D2KU_OK);
  assert(d2ku_rollback(&f.c, &f.r, &status) == D2KU_INVALID);
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK && !status.busy &&
         status.phase == D2KU_COMMITTED);
  d2ku_request check = {.command = D2KU_CMD_CHECK, .force = 1};
  assert(d2ku_dispatch(&f.c, &check, &status) == D2KU_OK);
  d2ku_daemon_work(&d);
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK && !status.busy &&
         status.phase == D2KU_COMMITTED);
  d2ku_request collision = {.command = D2KU_CMD_CHECK, .force = 1};
  strcpy(collision.transaction_id, f.r.transaction_id);
  assert(d2ku_dispatch(&f.c, &collision, &status) == D2KU_BUSY);
  collision.command = D2KU_CMD_SETTINGS; collision.force = 0;
  assert(d2ku_dispatch(&f.c, &collision, &status) == D2KU_BUSY);
  d.selected = 1; d.index = f.i; *d.manifest = f.m;
  d2ku_request later = f.r;
  strcpy(later.transaction_id, "later-download-failure");
  assert(d2ku_dispatch(&f.c, &later, &status) == D2KU_OK && status.busy);
  d2ku_daemon_work(&d);
  assert(d.status.last_result != D2KU_OK && !d.status.busy);
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK && !status.busy && status.phase == D2KU_COMMITTED);
  f.r.command = D2KU_CMD_ROLLBACK;
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_BUSY);
  f.r.command = D2KU_CMD_INSTALL;
  f.r.manifest_sha256[0] ^= 1;
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_BUSY);
  d2ku_daemon_destroy(&d);
  current(&f, "releases/B");
  check_file(f.c.root_dirfd, "state/knowledge", "candidate");
  cleanup(&f);
  puts("daemon replay: completed transaction survives subsequent "
       "check/restart; changed command/hash conflicts: PASS");
}
