#include "transaction_fixture.h"

#include "../src/daemon.h"
static char json[D2KU_IPC_MAX];
static void status_json(d2ku_daemon *d) {
  assert(d2ku_daemon_json(d, json, sizeof json) == D2KU_OK);
}
static void select_candidate(d2ku_daemon *d, fixture *f) {
  d->selected = 1; d->index = f->i; *d->manifest = f->m;
  d->status.available = 1;
}
static d2ku_rc untrusted(void *p, d2ku_clock_sample *s) {
  d2ku_rc rc = clock_sample(p, s); s->synchronized = 0; return rc;
}
static d2ku_rc no_sync(void *p, int fd) { (void)p; (void)fd; return D2KU_IO; }
static void unrelated(d2ku_daemon *d, fixture *f) {
  d2ku_status status;
  d2ku_request settings = {.command = D2KU_CMD_SETTINGS, .enabled = 0};
  assert(d2ku_dispatch(&f->c, &settings, &status) == D2KU_OK);
  d2ku_daemon_work(d);
  d2ku_request check = {.command = D2KU_CMD_CHECK, .force = 1};
  assert(d2ku_dispatch(&f->c, &check, &status) == D2KU_OK);
  d2ku_daemon_work(d);
}
int main(void) {
  fixture f; setup(&f); f.c.sync_fd = sync_crash;
  d2ku_daemon d; d2ku_status status;
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  status_json(&d);
  assert(strstr(json, "\"last_installation\":null") && strstr(json, "\"completed_utc\":null"));
  select_candidate(&d, &f); f.r.command = D2KU_CMD_INSTALL;
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK);
  assert(d2ku_install(&f.c, &f.r, &status) == D2KU_OK);
  /* Crash after terminal journal, before daemon outcome: never invent restart UTC. */
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  status_json(&d);
  assert(strstr(json, "\"last_installation\":{\"operation_id\":\"operation-1\""));
  assert(strstr(json, "\"completed_utc\":null"));
  d2ku_request rollback = {.command = D2KU_CMD_ROLLBACK};
  strcpy(rollback.transaction_id, "rollback-outcome"); strcpy(rollback.release_id, "A");
  memset(rollback.manifest_sha256, 1, 32);
  assert(d2ku_dispatch(&f.c, &rollback, &status) == D2KU_OK);
  d2ku_daemon_work(&d);
  assert(d.status.last_result == D2KU_OK);
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  unrelated(&d, &f); status_json(&d);
  assert(strstr(json, "\"last_installation\":{\"operation_id\":\"rollback-outcome\""));
  assert(strstr(json, "\"completed_utc\":1791060000"));
  select_candidate(&d, &f);
  strcpy(f.r.transaction_id, "metadata-failed");
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK);
  d2ku_daemon_work(&d); assert(d.status.last_result != D2KU_OK);
  unrelated(&d, &f);
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  status_json(&d);
  assert(strstr(json, "\"last_installation\":{\"operation_id\":\"metadata-failed\""));
  assert(strstr(json, "\"completed_utc\":1791060000"));
  select_candidate(&d, &f); f.c.clock.snapshot = untrusted;
  strcpy(f.r.transaction_id, "time-failed");
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK);
  d2ku_daemon_work(&d); status_json(&d);
  assert(strstr(json, "\"last_installation\":{\"operation_id\":\"time-failed\""));
  assert(strstr(json, "\"result\":9,\"phase\":0,\"completed_utc\":null"));
  f.c.clock.snapshot = clock_sample;
  strcpy(f.r.transaction_id, "outcome-fsync-failed");
  assert(d2ku_dispatch(&f.c, &f.r, &status) == D2KU_OK);
  f.c.sync_fd = no_sync;
  d2ku_daemon_work(&d);
  d2ku_request check = {.command = D2KU_CMD_CHECK, .force = 1};
  assert(d2ku_dispatch(&f.c, &check, &status) != D2KU_OK);
  f.c.sync_fd = sync_crash;
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  status_json(&d);
  assert(strstr(json, "\"last_installation\":{\"operation_id\":\"outcome-fsync-failed\""));
  assert(strstr(json, "\"result\":12,\"phase\":0,\"completed_utc\":null"));
  d2ku_daemon_destroy(&d);
  put(f.c.root_dirfd, "update-state/installation-result", "D2KI1 corrupt\n");
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_RECOVERY);
  current(&f, "releases/A"); check_file(f.c.root_dirfd, "state/knowledge", "candidate");
  cleanup(&f);
  setup(&f); f.failed = 1;
  assert(d2ku_install(&f.c, &f.r, &status) == D2KU_HEALTH);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  select_candidate(&d, &f); status_json(&d);
  assert(strstr(json, "\"quarantine\":{\"active\":true,\"applies_to_available\":true"));
  assert(strstr(json, "candidate health verification failed"));
  d.index.manifest_sha256[0] ^= 1; status_json(&d);
  assert(strstr(json, "\"quarantine\":{\"active\":true,\"applies_to_available\":false"));
  unrelated(&d, &f);
  /* Quarantine cause outlives journal rotation and generic last result. */
  assert(!unlinkat(f.c.root_dirfd, "update-state/journal.0", 0));
  assert(!unlinkat(f.c.root_dirfd, "update-state/journal.1", 0));
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &f.c) == D2KU_OK);
  status_json(&d); assert(strstr(json, "candidate health verification failed"));
  d2ku_daemon_destroy(&d); cleanup(&f);
  puts("outcome: completion bound to install/rollback, failures/time/restart/fsync, durable quarantine: PASS");
}
