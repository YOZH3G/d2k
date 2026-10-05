#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "daemon.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int identifier(const char *s) {
  size_t n = strnlen(s, 65);
  return n && n < 65 && s[0] != '.' &&
         strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
                   "789._-") == n;
}
static int digest(const char *b, size_t n, char out[65]) {
  unsigned char hash[32];
  unsigned size = 0;
  if (EVP_Digest(b, n, hash, &size, EVP_sha256(), NULL) != 1 || size != 32)
    return 0;
  for (size_t k = 0; k < 32; k++)
    snprintf(out + 2 * k, 3, "%02x", hash[k]);
  return 1;
}
static int encode(const d2ku_installation_outcome *o, char b[512]) {
  if (!o->present || !identifier(o->operation_id) ||
      !identifier(o->release_id) ||
      (o->command != D2KU_CMD_INSTALL && o->command != D2KU_CMD_ROLLBACK) ||
      o->result < D2KU_OK || o->result > D2KU_RECOVERY ||
      o->phase > D2KU_RECOVERY_FAILED || o->completed_utc < 0)
    return -1;
  char hash[65], seal[65];
  for (size_t k = 0; k < 32; k++)
    snprintf(hash + 2 * k, 3, "%02x", o->manifest_sha256[k]);
  int n = snprintf(b, 512, "D2KI1 %u %s %s %s %d %u %lld", o->command,
                   o->operation_id, o->release_id, hash, o->result, o->phase,
                   (long long)o->completed_utc);
  if (n < 0 || n >= 440 || !digest(b, (size_t)n, seal))
    return -1;
  return n + snprintf(b + n, 512 - (size_t)n, " %s\n", seal);
}
static d2ku_rc directory(d2ku_ctx *c, int *out) {
  int fd = openat(c->root_dirfd, "update-state",
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  struct stat st;
  if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 077)) {
    close(fd);
    return D2KU_INVALID;
  }
  *out = fd;
  return D2KU_OK;
}
static d2ku_rc load(d2ku_ctx *c, d2ku_installation_outcome *out) {
  int dir;
  d2ku_rc rc = directory(c, &dir);
  if (rc != D2KU_OK)
    return rc;
  int fd =
      openat(dir, "installation-result", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  close(dir);
  if (fd < 0)
    return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
  struct stat st;
  char b[512];
  ssize_t got;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_nlink != 1 || st.st_size <= 0 ||
      st.st_size >= 512 || (got = read(fd, b, sizeof b - 1)) != st.st_size) {
    close(fd);
    return D2KU_RECOVERY;
  }
  close(fd);
  b[got] = 0;
  d2ku_installation_outcome o = {.present = 1};
  unsigned command, phase;
  int result;
  long long at;
  char hash[65], checksum[65], tail, canonical[512];
  if (sscanf(b, "D2KI1 %u %64s %64s %64s %d %u %lld %64s %c", &command,
             o.operation_id, o.release_id, hash, &result, &phase, &at, checksum,
             &tail) != 8 ||
      strlen(hash) != 64 || strspn(hash, "0123456789abcdef") != 64)
    return D2KU_RECOVERY;
  o.command = (d2ku_command_op)command;
  o.phase = phase;
  o.result = (d2ku_rc)result;
  o.completed_utc = at;
  for (size_t k = 0; k < 32; k++) {
    char pair[3] = {hash[2 * k], hash[2 * k + 1], 0};
    o.manifest_sha256[k] = (unsigned char)strtoul(pair, NULL, 16);
  }
  int n = encode(&o, canonical);
  if (n != got || memcmp(b, canonical, (size_t)got))
    return D2KU_RECOVERY;
  *out = o;
  return D2KU_OK;
}
static d2ku_rc sync_file(d2ku_ctx *c, int fd) {
  if (c->sync_fd)
    return c->sync_fd(c->io_arg, fd);
  int r;
  do {
    r = fsync(fd);
  } while (r && errno == EINTR);
  return r ? D2KU_IO : D2KU_OK;
}
static d2ku_rc store(d2ku_ctx *c, const d2ku_installation_outcome *o) {
  char b[512];
  int n = encode(o, b);
  if (n < 0)
    return D2KU_INVALID;
  int dir;
  d2ku_rc rc = directory(c, &dir);
  if (rc != D2KU_OK)
    return rc;
  if (unlinkat(dir, "installation-result.new", 0) && errno != ENOENT) {
    close(dir);
    return D2KU_IO;
  }
  int fd = openat(dir, "installation-result.new",
                  O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    close(dir);
    return D2KU_IO;
  }
  size_t done = 0;
  while (done < (size_t)n) {
    ssize_t count = c->write_fd
                        ? c->write_fd(c->io_arg, fd, b + done, (size_t)n - done)
                        : write(fd, b + done, (size_t)n - done);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0 || (size_t)count > (size_t)n - done) {
      rc = D2KU_IO;
      break;
    }
    done += (size_t)count;
  }
  if (rc == D2KU_OK)
    rc = sync_file(c, fd);
  if (rc == D2KU_OK)
    rc = c->rename_at ? c->rename_at(c->io_arg, dir, "installation-result.new",
                                     dir, "installation-result")
         : renameat(dir, "installation-result.new", dir, "installation-result")
             ? D2KU_IO
             : D2KU_OK;
  if (rc == D2KU_OK)
    rc = sync_file(c, dir);
  close(fd);
  close(dir);
  return rc;
}
static d2ku_rc journal_result(const d2ku_journal *j) {
  if (j->phase == D2KU_COMMITTED)
    return D2KU_OK;
  if (j->phase == D2KU_ROLLED_BACK)
    return j->failure_reason == D2KU_OK ? D2KU_HEALTH : j->failure_reason;
  return D2KU_RECOVERY;
}
static void from_request(d2ku_installation_outcome *o, const d2ku_request *r,
                         d2ku_rc result) {
  memset(o, 0, sizeof *o);
  o->present = 1;
  o->command = r->command;
  o->result = result;
  strcpy(o->operation_id, r->transaction_id);
  strcpy(o->release_id, r->release_id);
  memcpy(o->manifest_sha256, r->manifest_sha256, 32);
}
d2ku_rc d2ku_outcome_complete(d2ku_daemon *d, const d2ku_request *request,
                              d2ku_rc result) {
  d2ku_installation_outcome o;
  from_request(&o, request, result);
  d2ku_journal j;
  if (d2ku_journal_load(d->ctx, &j) == D2KU_OK &&
      !strcmp(j.transaction_id, request->transaction_id))
    o.phase = j.phase;
  d2ku_clock_sample now;
  if (d2ku_read_clock(&d->ctx->clock, &now) == D2KU_OK)
    o.completed_utc = now.utc_seconds;
  d2ku_rc rc = store(d->ctx, &o);
  if (rc == D2KU_OK)
    d->last_installation = o;
  return rc;
}
d2ku_rc d2ku_outcome_reconcile(d2ku_daemon *d, int readonly) {
  d2ku_installation_outcome o = {0};
  d2ku_rc rc = load(d->ctx, &o);
  if (rc != D2KU_OK && rc != D2KU_ABSENT)
    return rc;
  const d2ku_request *r = &d->pending;
  int installation =
      r->command == D2KU_CMD_INSTALL || r->command == D2KU_CMD_ROLLBACK;
  if (installation && r->transaction_id[0]) {
    if (o.present && !strcmp(o.operation_id, r->transaction_id)) {
      if (o.command != r->command || strcmp(o.release_id, r->release_id) ||
          memcmp(o.manifest_sha256, r->manifest_sha256, 32))
        return D2KU_RECOVERY;
    } else {
      from_request(&o, r, d->status.last_result);
      d2ku_journal j;
      if (d2ku_journal_load(d->ctx, &j) == D2KU_OK &&
          !strcmp(j.transaction_id, r->transaction_id)) {
        o.phase = j.phase;
        o.result = journal_result(&j);
      }
      /* No durable event timestamp survived. Current/restart wall time is not
       * the time this request actually completed. */
      o.completed_utc = 0;
    }
    if (!readonly && (rc = store(d->ctx, &o)) != D2KU_OK)
      return rc;
    d->status.last_result = o.result;
  }
  d->last_installation = o;
  return D2KU_OK;
}
