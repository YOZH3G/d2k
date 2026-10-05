#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../src/daemon.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static uint64_t clock_ms = 1000;
static d2ku_rc sample(void *p, d2ku_clock_sample *s) {
  (void)p;
  memset(s, 0, sizeof *s);
  strcpy(s->boot_id, "test");
  strcpy(s->timezone, "UTC");
  s->mono_ms = clock_ms;
  s->local_date = 20261005;
  s->local_minute = 800;
  return D2KU_OK;
}
int main(void) {
  char root[] = "/tmp/d2ku-daemon-XXXXXX";
  assert(mkdtemp(root));
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  c.clock.snapshot = sample;
  c.trust_count = 1;
  c.trust[0].public_key[0] = 1;
  c.trust[0].not_after = INT64_MAX;
  d2ku_daemon d;
  assert(d2ku_daemon_init(&d, &c) == D2KU_OK);
  d2ku_request r = {.command = D2KU_CMD_STATUS};
  d2ku_status s;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && !s.operation_id[0]);
  r.command = D2KU_CMD_CHECK;
  strcpy(r.transaction_id, "client-operation");
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK);
  char id[65];
  strcpy(id, s.operation_id);
  assert(!strcmp(id, "client-operation"));
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && !strcmp(id, s.operation_id));
  r.command = D2KU_CMD_INSTALL;
  strcpy(r.release_id, "other");
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_BUSY);
  d2ku_daemon_work(&d);
  r.release_id[0] = 0;
  r.command = D2KU_CMD_STATUS;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && s.last_result == D2KU_TIME &&
         !s.busy);
  char json[4096];
  assert(d2ku_daemon_json(&d, json, sizeof json) == D2KU_OK);
  assert(strstr(json, "trusted synchronized time unavailable"));
  assert(strstr(json, "\"fresh\":true"));
  clock_ms += D2KU_CHECK_TTL_MS;
  assert(d2ku_daemon_json(&d, json, sizeof json) == D2KU_OK);
  assert(strstr(json, "\"fresh\":false"));
  clock_ms = 1000;
  r.command = D2KU_CMD_CHECK;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && !strcmp(id, s.operation_id) &&
         !s.busy);
  r.transaction_id[0] = 0;
  r.force = 1;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && strcmp(id, s.operation_id));
  d2ku_daemon_work(&d);
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &c) == D2KU_OK);
  r.command = D2KU_CMD_STATUS;
  r.force = 0;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && s.last_result == D2KU_TIME &&
         s.operation_id[0]);
  strcpy(r.transaction_id, s.operation_id);
  r.command = D2KU_CMD_CHECK;
  r.force = 1;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK && !s.busy);
  r.force = 0;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_BUSY);
  for (unsigned which = 0; which < 2; which++) {
    d2ku_clock_sample snapshot; sample(NULL, &snapshot);
    d2ku_rc failed = which ? D2KU_NETWORK : D2KU_TIME;
    assert(d2ku_cache_record(&d.status, &snapshot, failed) == D2KU_OK);
    d.status.last_result = failed;
    d2ku_request settings = {.command = D2KU_CMD_SETTINGS, .enabled = (int)which};
    assert(d2ku_dispatch(&c, &settings, &s) == D2KU_OK);
    d2ku_daemon_work(&d);
    assert(d.status.last_result == D2KU_OK);
    assert(d2ku_daemon_json(&d, json, sizeof json) == D2KU_OK);
    assert(strstr(json, "\"state\":\"error\""));
    assert(strstr(json, which ? "network transfer failed" : "trusted synchronized time unavailable"));
  }
  d2ku_daemon_destroy(&d);
  close(c.root_dirfd);
  char cmd[200];
  snprintf(cmd, sizeof cmd, "rm -rf %s", root);
  assert(system(cmd) == 0);
  puts("daemon: passive status, shared async operation, conflict, cached TIME, "
       "force, restart: PASS");
}
