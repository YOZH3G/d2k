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

/* Anonymous private download files are unlinked after opening. The transport
 * requires one link, so unlink only after successful fetch. No external path
 * or user-provided URL is involved. */
static d2ku_rc download(d2ku_daemon *d, const char *suffix, uint64_t max,
                        int *out, const char *retained) {
  char url[4096], name[80];
  if (snprintf(url, sizeof url, "%s/%s", d->feed, suffix) >= (int)sizeof url)
    return D2KU_INVALID;
  int dir = openat(d->ctx->root_dirfd, "update-state",
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (dir < 0)
    return D2KU_IO;
  snprintf(name, sizeof name, "%s", retained ? retained : "metadata-download");
  int fd = openat(dir, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
  if (fd < 0 && errno == EEXIST) {
    unlinkat(dir, name, 0);
    fd = openat(dir, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                0600);
  }
  if (fd < 0) {
    close(dir);
    return D2KU_IO;
  }
  d2ku_rc r = d2ku_fetch(d->ctx, url, fd, max);
  if (!retained || r != D2KU_OK)
    unlinkat(dir, name, 0);
  close(dir);
  if (r == D2KU_OK && lseek(fd, 0, SEEK_SET) < 0)
    r = D2KU_IO;
  if (r != D2KU_OK) {
    close(fd);
    return r;
  }
  *out = fd;
  return D2KU_OK;
}
static d2ku_rc bytes(d2ku_daemon *d, const char *suffix, size_t max,
                     unsigned char **out, size_t *len) {
  int fd = -1;
  d2ku_rc r = download(d, suffix, max, &fd, NULL);
  if (r != D2KU_OK)
    return r;
  struct stat st;
  if (fstat(fd, &st) || st.st_size <= 0 || (uint64_t)st.st_size > max) {
    close(fd);
    return D2KU_INVALID;
  }
  unsigned char *p = malloc((size_t)st.st_size);
  if (!p) {
    close(fd);
    return D2KU_IO;
  }
  size_t n = 0;
  while (n < (size_t)st.st_size) {
    ssize_t got = read(fd, p + n, (size_t)st.st_size - n);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0) {
      free(p);
      close(fd);
      return D2KU_IO;
    }
    n += (size_t)got;
  }
  close(fd);
  *out = p;
  *len = n;
  return D2KU_OK;
}
static d2ku_rc signed_bytes(d2ku_daemon *d, const char *name, size_t max,
                            unsigned char **out, size_t *len,
                            unsigned char sig[64]) {
  d2ku_rc r = bytes(d, name, max, out, len);
  if (r != D2KU_OK)
    return r;
  char path[512];
  if (snprintf(path, sizeof path, "%s.sig", name) >= (int)sizeof path) {
    free(*out);
    *out = NULL;
    return D2KU_INVALID;
  }
  unsigned char *s = NULL;
  size_t n = 0;
  r = bytes(d, path, 64, &s, &n);
  if (r == D2KU_OK && n != 64)
    r = D2KU_INVALID;
  if (r == D2KU_OK)
    memcpy(sig, s, 64);
  free(s);
  if (r != D2KU_OK) {
    free(*out);
    *out = NULL;
  }
  return r;
}
d2ku_rc d2ku_feed_check(d2ku_daemon *d, d2ku_index *i, d2ku_manifest *m) {
  d2ku_ctx *c = d->ctx;
  d2ku_persistent_state p;
  d2ku_rc r = d2ku_persistent_load(c, &p);
  if (r != D2KU_OK)
    return r;
  /* Load the independent trust record before any verification. */
  c->accepted_sequence = p.accepted_sequence;
  c->has_accepted_index = p.has_accepted_index;
  memcpy(c->accepted_index_sha256, p.accepted_index_sha256, 32);
  c->clock.last_accepted_timestamp = p.last_accepted_timestamp;
  c->trust_count = p.trust_count;
  memcpy(c->trust, p.trust, sizeof c->trust);
  unsigned char *b = NULL, sig[64];
  size_t n = 0;
  r = signed_bytes(d, "d2k-channel-stable/stable.json", D2KU_INDEX_MAX, &b, &n, sig);
  if (r != D2KU_OK)
    return r;
  r = d2ku_verify_index(c, b, n, sig, i);
  free(b);
  b = NULL;
  if (r != D2KU_OK)
    return r;
  char path[256];
  snprintf(path, sizeof path, "%s/manifest.json", i->release_id);
  r = signed_bytes(d, path, D2KU_MANIFEST_MAX, &b, &n, sig);
  if (r != D2KU_OK)
    return r;
  r = d2ku_verify_selected_manifest(c, i, b, n, sig, m);
  free(b);
  if (r != D2KU_OK && r != D2KU_INCOMPATIBLE)
    return r;
  d2ku_rc verified = r;
  int lock = -1;
  r = d2ku_maintenance_lock(c, &lock);
  if (r != D2KU_OK)
    return r;
  d2ku_persistent_state latest;
  r = d2ku_persistent_load(c, &latest);
  if (r == D2KU_OK && latest.sequence != p.sequence)
    r = D2KU_BUSY;
  if (r == D2KU_OK) {
    p.sequence++;
    p.accepted_sequence = i->sequence;
    p.has_accepted_index = 1;
    memcpy(p.accepted_index_sha256, i->document_sha256, 32);
    if (i->issued_at > p.last_accepted_timestamp)
      p.last_accepted_timestamp = i->issued_at;
    if (m->built_at > p.last_accepted_timestamp)
      p.last_accepted_timestamp = m->built_at;
    for (size_t k = 0; k < m->signing_key_count; k++) {
      size_t found = 0;
      while (found < p.trust_count && memcmp(p.trust[found].public_key,
                                             m->signing_keys[k].public_key, 32))
        found++;
      if (found == p.trust_count) {
        if (p.trust_count == D2KU_KEYS_MAX) {
          r = D2KU_INVALID;
          break;
        }
        p.trust[p.trust_count++] = m->signing_keys[k];
      }
    }
    if (r == D2KU_OK)
      r = d2ku_persistent_store(c, &p);
  }
  d2ku_maintenance_unlock(lock);
  if (r != D2KU_OK)
    return r;
  pthread_mutex_lock(&d->mutex);
  d->persistent = p;
  pthread_mutex_unlock(&d->mutex);
  c->accepted_sequence = p.accepted_sequence;
  c->has_accepted_index = p.has_accepted_index;
  memcpy(c->accepted_index_sha256, p.accepted_index_sha256, 32);
  c->clock.last_accepted_timestamp = p.last_accepted_timestamp;
  c->trust_count = p.trust_count;
  memcpy(c->trust, p.trust, sizeof c->trust);
  return verified;
}
/* One prepared archive is retained across the 05:00 boundary and reboot.
 * It has no authority by filename: every use verifies the current authenticated
 * package size/digest. At most this file and one bounded replacement exist. */
static int archive_valid(int fd, const d2ku_package *package) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_nlink != 1 || st.st_size < 0 ||
      (uint64_t)st.st_size != package->size || lseek(fd, 0, SEEK_SET) < 0)
    return 0;
  EVP_MD_CTX *digest = EVP_MD_CTX_new();
  if (!digest)
    return 0;
  int ok = EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1;
  unsigned char bytes[32768], actual[32];
  unsigned length = 0;
  uint64_t total = 0;
  while (ok && total < package->size) {
    size_t want = package->size - total < sizeof bytes
                      ? (size_t)(package->size - total)
                      : sizeof bytes;
    ssize_t got = read(fd, bytes, want);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0) {
      ok = 0;
      break;
    }
    total += (uint64_t)got;
    ok = EVP_DigestUpdate(digest, bytes, (size_t)got) == 1;
  }
  ok = ok && EVP_DigestFinal_ex(digest, actual, &length) == 1 && length == 32 &&
       !memcmp(actual, package->sha256, 32) && lseek(fd, 0, SEEK_SET) == 0;
  EVP_MD_CTX_free(digest);
  return ok;
}
static d2ku_rc prepared_archive(d2ku_daemon *d, const char *path,
                                const d2ku_package *package, int *out) {
  int dir = openat(d->ctx->root_dirfd, "update-state",
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir < 0)
    return D2KU_IO;
  int fd = openat(dir, "prepared-package", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd >= 0 && archive_valid(fd, package)) {
    pthread_mutex_lock(&d->mutex);
    d->status.received_bytes = package->size;
    pthread_mutex_unlock(&d->mutex);
    *out = fd;
    close(dir);
    return D2KU_OK;
  }
  if (fd >= 0)
    close(fd);
  /* These fixed private files are owned only by this serialized worker. */
  if (unlinkat(dir, "prepared-package", 0) && errno != ENOENT) {
    close(dir);
    return D2KU_IO;
  }
  d2ku_rc rc = download(d, path, package->size, &fd, "prepared-package.new");
  if (rc == D2KU_OK && !archive_valid(fd, package))
    rc = D2KU_UNTRUSTED;
  if (rc == D2KU_OK &&
      (fsync(fd) ||
       renameat(dir, "prepared-package.new", dir, "prepared-package") ||
       fsync(dir)))
    rc = D2KU_IO;
  if (rc == D2KU_OK)
    *out = fd;
  else {
    if (fd >= 0)
      close(fd);
    unlinkat(dir, "prepared-package.new", 0);
  }
  close(dir);
  return rc;
}
d2ku_rc d2ku_feed_archive(d2ku_daemon *d, const d2ku_manifest *m, int *fd) {
  for (size_t k = 0; k < m->package_count; k++)
    if (!strcmp(m->packages[k].abi, d->ctx->abi)) {
      char path[512];
      snprintf(path, sizeof path, "%s/%s", m->release_id,
               m->packages[k].artifact);
      pthread_mutex_lock(&d->mutex);
      d->status.total_bytes = m->packages[k].size;
      pthread_mutex_unlock(&d->mutex);
      return prepared_archive(d, path, &m->packages[k], fd);
    }
  return D2KU_INCOMPATIBLE;
}

/* Revalidate online metadata for each install operation. A changed channel
 * pointer is a conflict requiring a new displayed selection, never permission
 * to replace the user's ID/hash with latest. */
d2ku_rc d2ku_feed_pin(d2ku_daemon *d, d2ku_index *selected,
                      d2ku_manifest *manifest) {
  d2ku_index expected = *selected, fresh;
  d2ku_manifest *m = calloc(1, sizeof *m);
  if (!m)
    return D2KU_IO;
  d2ku_rc r = d2ku_feed_check(d, &fresh, m);
  if (r == D2KU_OK &&
      (strcmp(fresh.release_id, expected.release_id) ||
       memcmp(fresh.manifest_sha256, expected.manifest_sha256, 32)))
    r = D2KU_BUSY;
  if (r == D2KU_OK) {
    pthread_mutex_lock(&d->mutex);
    *manifest = *m;
    *selected = fresh;
    pthread_mutex_unlock(&d->mutex);
  }
  free(m);
  return r;
}
