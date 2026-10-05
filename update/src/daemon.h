#ifndef D2KU_DAEMON_H
#define D2KU_DAEMON_H
#include "d2k_update.h"
#include "d2k_update_ipc.h"
#include <pthread.h>
typedef struct {
  int present;
  d2ku_command_op command;
  char operation_id[65], release_id[65];
  unsigned char manifest_sha256[32];
  d2ku_rc result;
  unsigned phase;
  int64_t completed_utc; /* zero means unknown; exposed as JSON null */
} d2ku_installation_outcome;
typedef struct d2ku_daemon {
  pthread_mutex_t mutex;
  d2ku_ctx *ctx;
  d2ku_status status;
  d2ku_persistent_state persistent;
  d2ku_request pending;
  d2ku_index index;
  d2ku_manifest *manifest;
  int selected, pending_work, stop, handoff, outcome_blocked;
  d2ku_installation_outcome last_installation;
  char root[1024], feed[2048], timezone[D2KU_TIMEZONE_MAX + 1];
  d2ku_service_config services;
} d2ku_daemon;
d2ku_rc d2ku_daemon_open(d2ku_daemon *, d2ku_ctx *, int readonly);
d2ku_rc d2ku_daemon_init(d2ku_daemon *, d2ku_ctx *);
void d2ku_daemon_destroy(d2ku_daemon *);
void d2ku_daemon_work(d2ku_daemon *);
void d2ku_daemon_tick(d2ku_daemon *);
d2ku_rc d2ku_feed_check(d2ku_daemon *, d2ku_index *, d2ku_manifest *);
d2ku_rc d2ku_feed_pin(d2ku_daemon *, d2ku_index *, d2ku_manifest *);
d2ku_rc d2ku_feed_archive(d2ku_daemon *, const d2ku_manifest *, int *);
d2ku_rc d2ku_outcome_reconcile(d2ku_daemon *, int readonly);
d2ku_rc d2ku_outcome_complete(d2ku_daemon *, const d2ku_request *, d2ku_rc);
d2ku_rc d2ku_daemon_json_status(d2ku_daemon *, const d2ku_status *, char *,
                                size_t);
d2ku_rc d2ku_daemon_json(d2ku_daemon *, char *, size_t);
d2ku_rc d2ku_daemon_config(d2ku_daemon *, const char *);
d2ku_rc d2ku_daemon_refresh(void *);
d2ku_rc d2ku_platform_timezone(const char *);
d2ku_rc d2ku_platform_clock(d2ku_clock *);
#endif
