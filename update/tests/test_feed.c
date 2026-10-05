#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../src/daemon.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static d2ku_rc sample(void *p, d2ku_clock_sample *s) {
  (void)p;
  memset(s, 0, sizeof *s);
  s->utc_seconds = time(NULL);
  s->mono_ms = 1000;
  s->local_date = 20261005;
  s->local_minute = 800;
  s->synchronized = 1;
  strcpy(s->boot_id, "fixture");
  strcpy(s->timezone, "UTC");
  return D2KU_OK;
}
static d2ku_rc wall(void *p, int64_t *v) {
  (void)p;
  *v = time(NULL);
  return D2KU_OK;
}
int main(int argc, char **argv) {
  assert(argc == 2);
  d2ku_ctx c = {.updater_version = 1, .wire_version = 13, .state_version = 1};
  c.root_dirfd = open(argv[1], O_RDONLY | O_DIRECTORY);
  d2ku_daemon configured = {.ctx = &c};
  assert(d2ku_daemon_config(&configured, NULL) == D2KU_OK);
  char feed[2048];
  strcpy(feed, configured.feed);
  c.clock.snapshot = sample;
  c.clock.wall = wall;
  d2ku_daemon d;
  assert(d2ku_daemon_init(&d, &c) == D2KU_OK);
  strcpy(d.feed, feed);
  d2ku_request r = {.command = D2KU_CMD_CHECK};
  d2ku_status s;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK);
  d2ku_daemon_work(&d);
  r.command = D2KU_CMD_STATUS;
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_OK);
  assert(s.last_result == D2KU_OK && s.available && d.selected);
  assert(!strcmp(d.manifest->version, "fixture-version"));
  assert(c.accepted_sequence == 2);
  d2ku_persistent_state p;
  assert(d2ku_persistent_load(&c, &p) == D2KU_OK && p.accepted_sequence == 2 &&
         p.trust_count == 2);
  char json[D2KU_IPC_MAX];
  assert(d2ku_daemon_json(&d, json, sizeof json) == D2KU_OK);
  assert(strstr(json, "fixture-version") && strstr(json, "Signed fixture"));
  assert(d2ku_feed_pin(&d, &d.index, d.manifest) == D2KU_OK);
  d2ku_index wrong = d.index;
  wrong.manifest_sha256[0] ^= 1;
  assert(d2ku_feed_pin(&d, &wrong, d.manifest) == D2KU_BUSY);
  int fd = -1;
  assert(d2ku_feed_archive(&d, d.manifest, &fd) == D2KU_OK);
  char b[5] = {0};
  assert(read(fd, b, 4) == 4 && !strcmp(b, "data"));
  close(fd);
  /* Prepared packages survive operation completion/restart and require their
   * signed digest again. An unavailable feed must not discard a valid cache. */
  d2ku_manifest *saved = malloc(sizeof *saved);
  assert(saved);
  *saved = *d.manifest;
  d2ku_daemon_destroy(&d);
  assert(d2ku_daemon_init(&d, &c) == D2KU_OK);
  *d.manifest = *saved;
  free(saved);
  strcpy(d.feed, feed);
  char original[2048];
  strcpy(original, d.feed);
  strcpy(d.feed, "https://invalid.invalid");
  assert(d2ku_feed_archive(&d, d.manifest, &fd) == D2KU_OK);
  assert(read(fd, b, 4) == 4 && !strcmp(b, "data"));
  close(fd);
  strcpy(d.feed, original);
  r.command = D2KU_CMD_INSTALL;
  strcpy(r.release_id, "changed-latest");
  assert(d2ku_dispatch(&c, &r, &s) == D2KU_BUSY);
  d2ku_daemon_destroy(&d);
  close(c.root_dirfd);
  puts("feed: real HTTPS/signatures/pinned manifest/durable "
       "acceptance/archive: PASS");
}
