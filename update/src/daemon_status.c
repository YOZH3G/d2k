#define _POSIX_C_SOURCE 200809L
#include "daemon.h"
#include "transaction_internal.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
typedef struct {
  char *p;
  size_t n, cap;
  int bad;
} output;
static void add(output *o, const char *fmt, ...) {
  if (o->bad)
    return;
  va_list a;
  va_start(a, fmt);
  int n = vsnprintf(o->p + o->n, o->cap - o->n, fmt, a);
  va_end(a);
  if (n < 0 || (size_t)n >= o->cap - o->n)
    o->bad = 1;
  else
    o->n += (size_t)n;
}
static void quoted(output *o, const char *s) {
  add(o, "\"");
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\')
      add(o, "\\%c", c);
    else if (c < 32)
      add(o, "\\u%04x", c);
    else
      add(o, "%c", c);
  }
  add(o, "\"");
}
static void hash(output *o, const unsigned char *h) {
  add(o, "\"");
  for (size_t i = 0; i < 32; i++)
    add(o, "%02x", h[i]);
  add(o, "\"");
}
static const char *error_text(d2ku_rc result) {
  static const char *const messages[] = {
      "",
      "invalid request or metadata",
      "signature or trust verification failed",
      "selection expired; refresh required",
      "publication replay rejected; refresh required",
      "release incompatible with this device",
      "operation conflict; refresh status",
      "durable storage or local I/O failed",
      "network transfer failed",
      "trusted synchronized time unavailable",
      "candidate health verification failed",
      "required update state unavailable",
      "interrupted operation requires recovery"};
  return (unsigned)result < sizeof messages / sizeof messages[0]
             ? messages[result]
             : "unknown update error";
}
d2ku_rc d2ku_daemon_json_status(d2ku_daemon *d, const d2ku_status *view,
                                char *buf, size_t cap) {
  output o = {.p = buf, .cap = cap};
  pthread_mutex_lock(&d->mutex);
  d2ku_status observed = view ? *view : d->status;
  d2ku_clock_sample now = {0};
  if (d->ctx->clock.snapshot &&
      d->ctx->clock.snapshot(d->ctx->clock.arg, &now) == D2KU_OK)
    d2ku_cache_observe(&observed, &now);
  else
    observed.has_check = 0;
  int in_flight = observed.check_in_flight;
  observed.check_in_flight = 0;
  int fresh = !d2ku_check_due(&observed, now.mono_ms, 0);
  observed.check_in_flight = in_flight;
  const d2ku_status *s = &observed;
  char current[65] = "";
  d2ku_tx_current(d->ctx, current);
  d2ku_journal j;
  int journal = d2ku_journal_load(d->ctx, &j) == D2KU_OK;
  unsigned phase = s->phase;
  if (journal && !strcmp(j.transaction_id, s->operation_id))
    phase = j.phase;
  d2ku_rc visible_error = s->last_result;
  if (visible_error == D2KU_OK && s->has_check && s->check_result != D2KU_OK)
    visible_error = s->check_result;
  int current_verified = fresh && s->check_result == D2KU_OK && s->available &&
                         !strcmp(current, d->index.release_id);
  const char *state = s->busy                    ? "working"
                      : visible_error != D2KU_OK ? "error"
                      : current_verified         ? "current"
                      : s->available && strcmp(current, d->index.release_id)
                          ? "available"
                          : "unchecked";
  add(&o, "{\"state\":");
  quoted(&o, state);
  add(&o, ",\"operation_id\":");
  quoted(&o, s->operation_id);
  add(&o,
      ",\"phase\":%u,\"busy\":%s,\"received_bytes\":%llu,\"total_bytes\":%llu,"
      "\"current\":{\"release_id\":",
      phase, s->busy ? "true" : "false", (unsigned long long)s->received_bytes,
      (unsigned long long)s->total_bytes);
  quoted(&o, current);
  d2ku_source_kind source = D2KU_SOURCE_RUNTIME;
  d2ku_rc source_rc = current[0] ? d2ku_tx_source_kind(d->ctx, current, &source) : D2KU_ABSENT;
  add(&o, ",\"provenance\":");
  quoted(&o, source_rc == D2KU_OK && source == D2KU_SOURCE_LEGACY_LOCAL ? "legacy-local-v1" : source_rc == D2KU_OK ? "runtime" : "unverified");
  add(&o, ",\"legacy_restored\":%s,\"evidence\":", journal && j.phase == D2KU_ROLLED_BACK && j.old_kind == D2KU_SOURCE_LEGACY_LOCAL && source_rc == D2KU_OK && source == D2KU_SOURCE_LEGACY_LOCAL ? "true" : "false");
  quoted(&o, source_rc == D2KU_OK && source == D2KU_SOURCE_LEGACY_LOCAL ? "Owner-authorized local inventory; legacy Telegram listener/status is not a main-loop heartbeat or application success" : "");
  add(&o, "},\"previous\":");
  if (journal && j.phase == D2KU_COMMITTED && j.old_kind == D2KU_SOURCE_RUNTIME &&
      d2ku_tx_has_updater(d->ctx, j.old_release_id) == D2KU_OK) {
    add(&o, "{\"release_id\":");
    quoted(&o, j.old_release_id);
    add(&o, ",\"manifest_sha256\":");
    hash(&o, j.old_manifest_sha256);
    add(&o, "}");
  } else
    add(&o, "null");
  add(&o, ",\"available\":");
  if (s->available) {
    add(&o, "{\"release_id\":");
    quoted(&o, d->index.release_id);
    add(&o, ",\"manifest_sha256\":");
    hash(&o, d->index.manifest_sha256);
    add(&o, ",\"version\":");
    quoted(&o, d->manifest->version);
    add(&o, ",\"notes\":");
    quoted(&o, d->manifest->notes);
    add(&o, ",\"compatible\":%s}", d->selected ? "true" : "false");
  } else
    add(&o, "null");
  add(&o,
      ",\"check\":{\"cached\":%s,\"fresh\":%s,\"result\":%d,\"last_success_"
      "utc\":%lld},"
      "\"last_result\":%d,\"settings\":{\"enabled\":%s,\"window_start\":180,"
      "\"window_end\":300,\"selected_date\":%d,\"selected_minute\":%u,"
      "\"timezone\":",
      s->has_check ? "true" : "false", fresh ? "true" : "false",
      s->check_result, (long long)s->last_success_utc, s->last_result,
      s->enabled ? "true" : "false", d->persistent.policy.selected_date,
      d->persistent.policy.selected_minute);
  quoted(&o, d->timezone);
  add(&o, "},\"last_error\":");
  quoted(&o, error_text(visible_error));
  const d2ku_policy *policy = &d->persistent.policy;
  int quarantined = policy->has_quarantined_release;
  int applies =
      quarantined && s->available &&
      !memcmp(policy->quarantined_release_sha256, d->index.manifest_sha256, 32);
  add(&o,
      ",\"quarantine\":{\"active\":%s,\"applies_to_available\":%s,\"manifest_"
      "sha256\":",
      quarantined ? "true" : "false", applies ? "true" : "false");
  if (quarantined)
    hash(&o, policy->quarantined_release_sha256);
  else
    quoted(&o, "");
  add(&o, ",\"reason\":");
  quoted(&o, quarantined ? error_text(policy->quarantine_reason) : "");
  add(&o, "},\"last_installation\":");
  const d2ku_installation_outcome *last = &d->last_installation;
  if (!last->present)
    add(&o, "null");
  else {
    add(&o, "{\"operation_id\":");
    quoted(&o, last->operation_id);
    add(&o, ",\"release_id\":");
    quoted(&o, last->release_id);
    add(&o, ",\"result\":%d,\"phase\":%u,\"completed_utc\":", last->result,
        last->phase);
    if (last->completed_utc)
      add(&o, "%lld", (long long)last->completed_utc);
    else
      add(&o, "null");
    add(&o, ",\"reason\":");
    quoted(&o, error_text(last->result));
    add(&o, "}");
  }
  add(&o, ",\"completed_utc\":");
  if (last->present && last->completed_utc)
    add(&o, "%lld", (long long)last->completed_utc);
  else
    add(&o, "null");
  add(&o, "}");
  pthread_mutex_unlock(&d->mutex);
  return o.bad ? D2KU_INVALID : D2KU_OK;
}

d2ku_rc d2ku_daemon_json(d2ku_daemon *d, char *buf, size_t cap) {
  return d2ku_daemon_json_status(d, NULL, buf, cap);
}
