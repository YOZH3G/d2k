#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#include "daemon.h"
#include "transaction_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void apply(d2ku_daemon *d, const d2ku_persistent_state *p) {
  pthread_mutex_lock(&d->mutex);
  d->persistent = *p;
  d2ku_ctx *c = d->ctx;
  c->accepted_sequence = p->accepted_sequence;
  c->has_accepted_index = p->has_accepted_index;
  memcpy(c->accepted_index_sha256, p->accepted_index_sha256, 32);
  c->clock.last_accepted_timestamp = p->last_accepted_timestamp;
  c->trust_count = p->trust_count;
  memcpy(c->trust, p->trust, sizeof c->trust);
  d->status.enabled = p->policy.enabled;
  pthread_mutex_unlock(&d->mutex);
}
static int valid_id(const char *id) {
  size_t n = strnlen(id, 65);
  return n && n < 65 &&
         strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
                    "6789._-") == n &&
         id[0] != '.';
}
static int result_encode(d2ku_daemon *d, char *b, size_t cap) {
  char hash[65];
  for (size_t k = 0; k < 32; k++)
    snprintf(hash + k * 2, 3, "%02x", d->pending.manifest_sha256[k]);
  return snprintf(b, cap, "D2KD2 %s %u %d %d %s %s %d %d %lld\n",
                  d->status.operation_id, (unsigned)d->pending.command,
                  d->pending.force, d->pending.enabled,
                  d->pending.release_id[0] ? d->pending.release_id : "-", hash,
                  d->status.busy, (int)d->status.last_result,
                  (long long)d->status.last_success_utc);
}
static d2ku_rc result_file(d2ku_daemon *d, int save, const char *name) {
  int dir = openat(d->ctx->root_dirfd, "update-state",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir < 0)
    return !save && errno == ENOENT ? D2KU_OK : D2KU_IO;
  char b[512], temporary[80];
  snprintf(temporary, sizeof temporary, "%s.new", name);
  int fd = -1;
  d2ku_rc r = D2KU_IO;
  if (save) {
    int n = result_encode(d, b, sizeof b);
    if (n < 0 || n >= (int)sizeof b) {
      close(dir);
      return D2KU_INVALID;
    }
    fd = openat(dir, temporary,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) {
      unlinkat(dir, temporary, 0);
      fd = openat(dir, temporary,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    }
    if (fd >= 0 && write(fd, b, (size_t)n) == n && !fsync(fd) &&
        !renameat(dir, temporary, dir, name) && !fsync(dir))
      r = D2KU_OK;
  } else {
    fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT)
      r = D2KU_OK;
    struct stat st;
    ssize_t n;
    if (fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 077) && st.st_nlink == 1 &&
        st.st_size > 0 && st.st_size < (off_t)sizeof b &&
        (n = read(fd, b, sizeof b - 1)) == st.st_size) {
      b[n] = 0;
      char id[65], release[65], hash[65], extra;
      unsigned op;
      int force, enabled, busy, rc;
      long long at;
      if (sscanf(b, "D2KD2 %64s %u %d %d %64s %64s %d %d %lld %c", id, &op,
                 &force, &enabled, release, hash, &busy, &rc, &at,
                 &extra) == 9 &&
          valid_id(id) && op >= D2KU_CMD_CHECK && op <= D2KU_CMD_SETTINGS &&
          (force == 0 || force == 1) && (enabled == 0 || enabled == 1) &&
          (busy == 0 || busy == 1) && rc >= 0 && rc <= D2KU_RECOVERY &&
          at >= 0 && strlen(hash) == 64 &&
          strspn(hash, "0123456789abcdef") == 64 &&
          (!strcmp(release, "-") || valid_id(release))) {
        strcpy(d->status.operation_id, id);
        strcpy(d->pending.transaction_id, id);
        d->pending.command = (d2ku_command_op)op;
        d->pending.force = force;
        d->pending.enabled = enabled;
        if (strcmp(release, "-"))
          strcpy(d->pending.release_id, release);
        for (size_t k = 0; k < 32; k++) {
          char pair[3] = {hash[k * 2], hash[k * 2 + 1], 0};
          d->pending.manifest_sha256[k] =
              (unsigned char)strtoul(pair, NULL, 16);
        }
        d->status.last_result = (d2ku_rc)rc;
        d->status.last_success_utc = at;
        d->status.has_success = at > 0;
        d->status.busy = busy;
        char canonical[512];
        int len = result_encode(d, canonical, sizeof canonical);
        if (len == n && !memcmp(b, canonical, (size_t)n)) {
          r = D2KU_OK;
          d->status.busy = 0;
          if (busy)
            d->status.last_result = D2KU_RECOVERY;
        }
      }
    }
  }
  if (fd >= 0)
    close(fd);
  close(dir);
  return r;
}
d2ku_rc d2ku_daemon_open(d2ku_daemon *d, d2ku_ctx *c, int readonly) {
  if (!d || !c)
    return D2KU_INVALID;
  memset(d, 0, sizeof *d);
  d->ctx = c;
  if (pthread_mutex_init(&d->mutex, NULL))
    return D2KU_IO;
  d->manifest = calloc(1, sizeof *d->manifest);
  if (!d->manifest) {
    pthread_mutex_destroy(&d->mutex);
    return D2KU_IO;
  }
  c->daemon = d;
  d2ku_persistent_state p;
  d2ku_rc r = d2ku_persistent_load(c, &p);
  if (r == D2KU_ABSENT) {
    memset(&p, 0, sizeof p);
    p.schema = 1;
    p.sequence = 1;
    p.policy.enabled = 1;
    p.trust_count = c->trust_count;
    memcpy(p.trust, c->trust, sizeof p.trust);
    r = readonly ? D2KU_OK : d2ku_persistent_store(c, &p);
  }
  if (r == D2KU_OK) {
    apply(d, &p);
    r = result_file(d, 0, "daemon-result");
    d2ku_journal j;
    if (r == D2KU_OK && d2ku_journal_load(c, &j) == D2KU_OK &&
        !strcmp(j.transaction_id, d->status.operation_id)) {
      d->status.phase = j.phase;
      if (j.phase == D2KU_COMMITTED)
        d->status.last_result = D2KU_OK;
      else if (j.phase == D2KU_ROLLED_BACK)
        d->status.last_result = D2KU_HEALTH;
    }
  }
  if (r != D2KU_OK)
    d2ku_daemon_destroy(d);
  return r;
}
d2ku_rc d2ku_daemon_init(d2ku_daemon *d, d2ku_ctx *c) {
  return d2ku_daemon_open(d, c, 0);
}
void d2ku_daemon_destroy(d2ku_daemon *d) {
  free(d->manifest);
  d->manifest = NULL;
  if (d->ctx)
    d->ctx->daemon = NULL;
  pthread_mutex_destroy(&d->mutex);
}
static d2ku_rc operation_id(char out[65]) {
  unsigned char random[16];
  if (RAND_bytes(random, sizeof random) != 1)
    return D2KU_IO;
  for (size_t i = 0; i < sizeof random; i++)
    snprintf(out + i * 2, 3, "%02x", random[i]);
  return D2KU_OK;
}
d2ku_rc d2ku_dispatch(d2ku_ctx *c, const d2ku_request *r, d2ku_status *s) {
  if (!c || !r || !s || !c->daemon)
    return D2KU_INVALID;
  d2ku_daemon *d = c->daemon;
  pthread_mutex_lock(&d->mutex);
  d2ku_rc rc = D2KU_OK;
  if (r->command == D2KU_CMD_STATUS)
    goto done;
  if (r->transaction_id[0]) {
    if (!valid_id(r->transaction_id)) {
      rc = D2KU_INVALID;
      goto done;
    }
    if (!strcmp(r->transaction_id, d->status.operation_id)) {
      if (r->command != d->pending.command || r->force != d->pending.force ||
          r->enabled != d->pending.enabled ||
          strcmp(r->release_id, d->pending.release_id) ||
          memcmp(r->manifest_sha256, d->pending.manifest_sha256, 32))
        rc = D2KU_BUSY;
      goto done;
    }
    if (r->command == D2KU_CMD_INSTALL || r->command == D2KU_CMD_ROLLBACK) {
      d2ku_journal j;
      if (d2ku_journal_load(c, &j) == D2KU_OK &&
          !strcmp(j.transaction_id, r->transaction_id)) {
        d2ku_daemon prior = {.ctx = c};
        d2ku_rc loaded = result_file(&prior, 0, "daemon-transaction");
        if (loaded != D2KU_OK ||
            strcmp(prior.status.operation_id, r->transaction_id) ||
            prior.pending.command != r->command ||
            prior.pending.force != r->force ||
            prior.pending.enabled != r->enabled ||
            strcmp(j.new_release_id, r->release_id) ||
            memcmp(j.new_manifest_sha256, r->manifest_sha256, 32)) {
          rc = D2KU_BUSY;
          goto done;
        }
        *s = d->status;
        strcpy(s->operation_id, j.transaction_id);
        s->phase = j.phase;
        s->busy = j.phase != D2KU_COMMITTED && j.phase != D2KU_ROLLED_BACK &&
                  j.phase != D2KU_RECOVERY_FAILED;
        s->last_result = j.phase == D2KU_COMMITTED     ? D2KU_OK
                         : j.phase == D2KU_ROLLED_BACK ? D2KU_HEALTH
                                                       : D2KU_RECOVERY;
        pthread_mutex_unlock(&d->mutex);
        return D2KU_OK;
      }
    }
  }
  if (r->command < D2KU_CMD_CHECK || r->command > D2KU_CMD_SETTINGS) {
    rc = D2KU_INVALID;
    goto done;
  }
  if (d->status.busy) {
    if (r->command != d->pending.command ||
        (r->command == D2KU_CMD_SETTINGS && r->enabled != d->pending.enabled) ||
        ((r->command == D2KU_CMD_INSTALL || r->command == D2KU_CMD_ROLLBACK) &&
         (strcmp(r->release_id, d->pending.release_id) ||
          memcmp(r->manifest_sha256, d->pending.manifest_sha256, 32))))
      rc = D2KU_BUSY;
    goto done;
  }
  if (d->stop || d->handoff) {
    rc = D2KU_BUSY;
    goto done;
  }
  if (r->command == D2KU_CMD_CHECK) {
    d2ku_clock_sample now = {0};
    if (c->clock.snapshot)
      c->clock.snapshot(c->clock.arg, &now);
    d2ku_cache_observe(&d->status, &now);
    if (!d2ku_check_due(&d->status, now.mono_ms, r->force))
      goto done;
  }
  if (r->command == D2KU_CMD_INSTALL &&
      (!d->selected || strcmp(r->release_id, d->index.release_id) ||
       memcmp(r->manifest_sha256, d->index.manifest_sha256, 32))) {
    rc = D2KU_BUSY;
    goto done;
  }
  if (r->transaction_id[0]) {
    strcpy(d->status.operation_id, r->transaction_id);
    rc = D2KU_OK;
  } else
    rc = operation_id(d->status.operation_id);
  if (rc != D2KU_OK)
    goto done;
  d->pending = *r;
  strcpy(d->pending.transaction_id, d->status.operation_id);
  if (r->automatic) {
    rc = d2ku_auto_reserve(c, &d->pending);
    if (rc != D2KU_OK)
      goto done;
  }
  d->status.busy = 1;
  d->pending_work = 1;
  d->status.check_in_flight = r->command == D2KU_CMD_CHECK;
  d->status.received_bytes = 0;
  d->status.total_bytes = 0;
  d->status.phase = r->command == D2KU_CMD_CHECK     ? D2KU_CHECKING
                    : r->command == D2KU_CMD_INSTALL ? D2KU_DOWNLOADING
                                                     : 0;
  if (r->command == D2KU_CMD_INSTALL || r->command == D2KU_CMD_ROLLBACK)
    rc = result_file(d, 1, "daemon-transaction");
  if (rc == D2KU_OK)
    rc = result_file(d, 1, "daemon-result");
  if (rc != D2KU_OK) {
    d->pending_work = 0;
    d->status.busy = 0;
    d->status.check_in_flight = 0;
    d->status.last_result = rc;
  }
done:
  *s = d->status;
  pthread_mutex_unlock(&d->mutex);
  return rc;
}
static d2ku_rc install(d2ku_daemon *d, d2ku_request *r, d2ku_status *s) {
  d2ku_ctx *c = d->ctx;
  d2ku_clock_sample now;
  d2ku_rc rc = d2ku_read_clock(&c->clock, &now);
  if (rc != D2KU_OK)
    return rc;
  d2ku_journal j;
  rc = d2ku_tx_current(c, r->expected_release_id);
  if (rc != D2KU_OK)
    return rc;
  rc = d2ku_tx_receipt(c, r->expected_release_id, r->expected_manifest_sha256);
  if (rc != D2KU_OK)
    return rc;
  if (r->command == D2KU_CMD_ROLLBACK) {
    rc = d2ku_journal_load(c, &j);
    if (rc != D2KU_OK)
      return rc;
    return d2ku_rollback(c, r, s);
  }
  r->index = &d->index;
  r->manifest = d->manifest;
  r->archive_fd = -1;
  /* A cached signed selection never bypasses expiry, anti-replay or time
   * floors. */
  if (d->index.expires_at <= now.utc_seconds)
    return D2KU_EXPIRED;
  if (d->index.sequence != c->accepted_sequence ||
      memcmp(d->index.document_sha256, c->accepted_index_sha256, 32))
    return D2KU_REPLAY;
  rc = d2ku_feed_pin(d, &d->index, d->manifest);
  if (rc != D2KU_OK)
    return rc;
  rc = d2ku_feed_archive(d, d->manifest, &r->archive_fd);
  if (rc == D2KU_OK)
    rc = d2ku_install(c, r, s);
  if (r->archive_fd >= 0)
    close(r->archive_fd);
  return rc;
}
void d2ku_daemon_work(d2ku_daemon *d) {
  pthread_mutex_lock(&d->mutex);
  if (!d->pending_work) {
    pthread_mutex_unlock(&d->mutex);
    return;
  }
  d->pending_work = 0;
  d2ku_request r = d->pending;
  pthread_mutex_unlock(&d->mutex);
  d2ku_rc rc = D2KU_OK;
  if (d->ctx->refresh) {
    int lock = -1;
    rc = d2ku_maintenance_lock(d->ctx, &lock);
    if (rc == D2KU_OK) {
      rc = d->ctx->refresh(d->ctx->refresh_arg);
      d2ku_maintenance_unlock(lock);
    }
  }
  d2ku_status health = {0};
  d2ku_index index = {0};
  d2ku_manifest *m = calloc(1, sizeof *m);
  if (!m)
    rc = D2KU_IO;
  if (rc != D2KU_OK) { /* Preserve configuration/locking failure without network
                          I/O. */
  } else if (r.command == D2KU_CMD_CHECK) {
    d2ku_clock_sample now;
    rc = d2ku_read_clock(&d->ctx->clock, &now);
    if (rc == D2KU_OK)
      rc = d2ku_feed_check(d, &index, m);
  } else if (r.command == D2KU_CMD_SETTINGS) {
    int lock = -1;
    rc = d2ku_maintenance_lock(d->ctx, &lock);
    if (rc == D2KU_OK) {
      d2ku_persistent_state p;
      rc = d2ku_persistent_load(d->ctx, &p);
      if (rc == D2KU_OK) {
        p.sequence++;
        p.policy.enabled = r.enabled;
        rc = d2ku_persistent_store(d->ctx, &p);
        if (rc == D2KU_OK)
          apply(d, &p);
      }
      d2ku_maintenance_unlock(lock);
    }
  } else
    rc = install(d, &r, &health);
  pthread_mutex_lock(&d->mutex);
  d->status.last_result = rc;
  if (r.command == D2KU_CMD_CHECK) {
    d2ku_clock_sample now = {0};
    if (d->ctx->clock.snapshot)
      d->ctx->clock.snapshot(d->ctx->clock.arg, &now);
    (void)d2ku_cache_record(&d->status, &now, rc);
    if (rc == D2KU_OK || rc == D2KU_INCOMPATIBLE) {
      d->index = index;
      *d->manifest = *m;
      d->selected = rc == D2KU_OK;
      d->status.available = 1;
      d->status.phase = D2KU_AVAILABLE;
    }
  }
  if ((r.command == D2KU_CMD_INSTALL || r.command == D2KU_CMD_ROLLBACK) &&
      rc == D2KU_OK)
    d->handoff = 1;
  d->status.busy = 0;
  d->status.check_in_flight = 0;
  if (result_file(d, 1, "daemon-result") != D2KU_OK)
    d->status.last_result = D2KU_IO;
  pthread_mutex_unlock(&d->mutex);
  free(m);
}
void d2ku_daemon_tick(d2ku_daemon *d) {
  pthread_mutex_lock(&d->mutex);
  int busy = d->status.busy || d->stop || d->handoff;
  pthread_mutex_unlock(&d->mutex);
  if (busy)
    return;
  d2ku_clock_sample now;
  if (d2ku_read_clock(&d->ctx->clock, &now) != D2KU_OK)
    return;
  d2ku_persistent_state p;
  int lock = -1;
  if (d2ku_maintenance_lock(d->ctx, &lock) != D2KU_OK)
    return;
  d2ku_rc rc = d2ku_persistent_load(d->ctx, &p);
  if (rc == D2KU_OK && now.local_date > p.policy.selected_date) {
    unsigned char random;
    do {
      if (RAND_bytes(&random, 1) != 1) {
        rc = D2KU_IO;
        break;
      }
    } while (random >= 240);
    if (rc == D2KU_OK)
      rc = d2ku_select_minute(&p.policy, now.local_date, random % 120);
    if (rc == D2KU_OK) {
      p.sequence++;
      rc = d2ku_persistent_store(d->ctx, &p);
    }
  }
  if (rc == D2KU_OK)
    apply(d, &p);
  d2ku_maintenance_unlock(lock);
  if (rc != D2KU_OK)
    return;
  if (now.local_minute < 180 || now.local_minute >= 300)
    return;
  d2ku_request r = {.command = D2KU_CMD_CHECK};
  d2ku_status s;
  pthread_mutex_lock(&d->mutex);
  int due = d2ku_check_due(&d->status, now.mono_ms, 0);
  int selected = d->selected && d->status.check_result == D2KU_OK;
  char active[65] = "";
  d2ku_tx_current(d->ctx, active);
  if (!due && selected && strcmp(active, d->index.release_id) &&
      d2ku_auto_due(&p.policy, &d->ctx->clock) &&
      d2ku_auto_release_allowed(&p.policy, d->index.manifest_sha256)) {
    r.command = D2KU_CMD_INSTALL;
    r.automatic = 1;
    strcpy(r.release_id, d->index.release_id);
    memcpy(r.manifest_sha256, d->index.manifest_sha256, 32);
  }
  pthread_mutex_unlock(&d->mutex);
  if (due || r.command == D2KU_CMD_INSTALL)
    (void)d2ku_dispatch(d->ctx, &r, &s);
}
