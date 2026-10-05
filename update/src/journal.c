#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "d2k_update.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define RECORD_MAX 4096u
#define HEADER_SIZE 56u
/* All integers are network-byte-order; no C object representation is persisted. */
typedef struct { unsigned char b[RECORD_MAX]; size_t n, pos; int bad; } buffer;
typedef enum { JOURNAL, PERSISTENT } kind;
static void bytes(buffer *b, const void *p, size_t n)
{
    if (n > sizeof(b->b) - b->n) { b->bad = 1; return; }
    memcpy(b->b + b->n, p, n); b->n += n;
}
static void number(buffer *b, uint64_t v, unsigned width)
{
    unsigned char p[8];
    for (unsigned i = 0; i < width; i++) p[width - 1 - i] = (unsigned char)(v >> (8*i));
    bytes(b, p, width);
}
static uint64_t getnum(buffer *b, unsigned width)
{
    uint64_t v = 0;
    if (width > b->n - b->pos) { b->bad = 1; return 0; }
    for (unsigned i = 0; i < width; i++) v = (v << 8) | b->b[b->pos++];
    return v;
}
static void getbytes(buffer *b, void *p, size_t n)
{
    if (n > b->n - b->pos) { b->bad = 1; return; }
    memcpy(p, b->b + b->pos, n); b->pos += n;
}
static int textvalid(const char *s, size_t n, size_t max, int id)
{
    if (!n || n > max || s[n]) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        int alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (id ? (!alnum && (i == 0 || (c != '.' && c != '_' && c != '-'))) : (c < 33 || c > 126)) return 0;
    }
    return 1;
}
static void putstr(buffer *b, const char *s, size_t n) { number(b, n, 2); bytes(b, s, n); }
static size_t getstr(buffer *b, char *s, size_t max)
{
    size_t n = (size_t)getnum(b, 2);
    if (n > max) { b->bad = 1; return 0; }
    getbytes(b, s, n); s[n] = 0; return n;
}
static int boolean(int n) { return n == 0 || n == 1; }
static int datevalid(int32_t date)
{
    if (!date) return 1;
    if (date < 19700101 || date > 99991231) return 0;
    int y = date / 10000, m = date / 100 % 100, d = date % 100;
    const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (m < 1 || m > 12 || d < 1) return 0;
    return d <= (int)(days[m-1] + (m == 2 && y%4 == 0 && (y%100 != 0 || y%400 == 0)));
}
static d2ku_rc journal_valid(const d2ku_journal *j)
{
    if (j->schema != 1) return D2KU_INCOMPATIBLE;
    if (!j->sequence || !textvalid(j->transaction_id, j->transaction_id_len, D2KU_ID_MAX, 1) ||
        !textvalid(j->old_release_id, j->old_release_id_len, D2KU_ID_MAX, 1) ||
        !textvalid(j->new_release_id, j->new_release_id_len, D2KU_ID_MAX, 1) ||
        !textvalid(j->progress_boot_id, j->progress_boot_id_len, D2KU_BOOT_ID_MAX, 0) ||
        j->phase < D2KU_CHECKING || j->phase > D2KU_RECOVERY_FAILED ||
        !boolean(j->snapshot_ready) || j->progress_utc < 0 ||
        j->failure_reason < D2KU_OK || j->failure_reason > D2KU_RECOVERY ||
        j->recovery_reason < D2KU_OK || j->recovery_reason > D2KU_RECOVERY) return D2KU_INVALID;
    if (j->phase >= D2KU_SWITCHING && j->phase <= D2KU_COMMITTED && !j->snapshot_ready)
        return D2KU_INVALID;
    return D2KU_OK;
}
static d2ku_rc persistent_valid(const d2ku_persistent_state *s)
{
    if (s->schema != 1) return D2KU_INCOMPATIBLE;
    const d2ku_policy *p = &s->policy;
    if (!s->sequence || !boolean(s->has_accepted_index) ||
        (s->has_accepted_index ? !s->accepted_sequence : s->accepted_sequence != 0) ||
        s->last_accepted_timestamp < 0 || !s->trust_count || s->trust_count > D2KU_KEYS_MAX ||
        !boolean(p->enabled) || !boolean(p->has_quarantined_release) ||
        !datevalid(p->selected_date) || !datevalid(p->last_attempt_date) ||
        (p->selected_date ? (p->selected_minute < 180 || p->selected_minute > 299) : p->selected_minute != 0))
        return D2KU_INVALID;
    if (s->auto_operation[0] &&
        (!textvalid(s->auto_operation, strnlen(s->auto_operation, 65), 64, 1) ||
         !textvalid(s->auto_release, strnlen(s->auto_release, 65), 64, 1) ||
         !p->last_attempt_date))
      return D2KU_INVALID;
    if (!s->auto_operation[0] && s->auto_release[0])
      return D2KU_INVALID;
    for (size_t i = 0; i < s->trust_count; i++) {
        if (s->trust[i].not_before < 0 || s->trust[i].not_after <= s->trust[i].not_before) return D2KU_INVALID;
        for (size_t k = 0; k < i; k++)
            if (!memcmp(s->trust[i].public_key, s->trust[k].public_key, 32)) return D2KU_INVALID;
    }
    return D2KU_OK;
}
static void encode_journal(buffer *b, const d2ku_journal *j)
{
    putstr(b, j->transaction_id, j->transaction_id_len); number(b, j->phase, 4);
    number(b, j->failure_reason, 4); number(b, j->recovery_reason, 4);
    putstr(b, j->old_release_id, j->old_release_id_len); putstr(b, j->new_release_id, j->new_release_id_len);
    bytes(b, j->old_manifest_sha256, 32); bytes(b, j->new_manifest_sha256, 32);
    number(b, (unsigned)j->snapshot_ready, 1); number(b, j->active_services, 8);
    number(b, j->progress_mono_ms, 8); number(b, (uint64_t)j->progress_utc, 8);
    putstr(b, j->progress_boot_id, j->progress_boot_id_len);
}
static void encode_persistent(buffer *b, const d2ku_persistent_state *s)
{
    number(b, s->accepted_sequence, 8); bytes(b, s->accepted_index_sha256, 32);
    number(b, (unsigned)s->has_accepted_index, 1); number(b, (uint64_t)s->last_accepted_timestamp, 8);
    number(b, s->trust_count, 1);
    for (size_t i = 0; i < s->trust_count; i++) {
        bytes(b, s->trust[i].public_key, 32); number(b, (uint64_t)s->trust[i].not_before, 8);
        number(b, (uint64_t)s->trust[i].not_after, 8);
    }
    const d2ku_policy *p = &s->policy;
    number(b, (unsigned)p->enabled, 1); number(b, (uint32_t)p->selected_date, 4);
    number(b, (uint32_t)p->last_attempt_date, 4); number(b, p->selected_minute, 2);
    number(b, (unsigned)p->has_quarantined_release, 1); bytes(b, p->quarantined_release_sha256, 32);
    putstr(b, s->auto_operation, strlen(s->auto_operation));
    putstr(b, s->auto_release, strlen(s->auto_release));
    bytes(b, s->auto_manifest_sha256, 32);
}
static int digest(const void *p, size_t n, unsigned char sha[32])
{
    unsigned len = 0; return EVP_Digest(p, n, sha, &len, EVP_sha256(), NULL) == 1 && len == 32;
}
static const char *magic(kind k) { return k == JOURNAL ? "D2KJNL01" : "D2KPER01"; }
static d2ku_rc encode(kind k, const void *record, buffer *b)
{
    d2ku_rc rc = k == JOURNAL ? journal_valid(record) : persistent_valid(record);
    if (rc != D2KU_OK) return rc;
    uint64_t seq = k == JOURNAL ? ((const d2ku_journal *)record)->sequence : ((const d2ku_persistent_state *)record)->sequence;
    memset(b, 0, sizeof *b); b->n = HEADER_SIZE;
    if (k == JOURNAL) encode_journal(b, record); else encode_persistent(b, record);
    size_t len = b->n; b->n = 0;
    bytes(b, magic(k), 8); number(b, 1, 4); number(b, len, 4); number(b, seq, 8);
    /* Hash entire record with its checksum bytes zero, binding schema/seq/type. */
    b->n = len;
    unsigned char sha[32]; if (b->bad || !digest(b->b, len, sha)) return D2KU_IO;
    memcpy(b->b + 24, sha, 32); return D2KU_OK;
}
static d2ku_rc decode(kind k, buffer *b, unsigned slot, void *out)
{
    if (b->n < HEADER_SIZE || memcmp(b->b, magic(k), 8)) return D2KU_RECOVERY;
    b->pos = 8;
    uint64_t schema = getnum(b, 4), len = getnum(b, 4), seq = getnum(b, 8);
    unsigned char saved[32], sha[32]; getbytes(b, saved, 32);
    if (schema != 1 || len != b->n || !seq || seq%2 != slot) return D2KU_RECOVERY;
    memset(b->b + 24, 0, 32);
    int ok = digest(b->b, b->n, sha) && !memcmp(saved, sha, 32);
    memcpy(b->b + 24, saved, 32); if (!ok) return D2KU_RECOVERY;
    if (k == JOURNAL) {
        d2ku_journal j = {0}; j.schema = 1; j.sequence = seq; memcpy(j.checksum, saved, 32);
        j.transaction_id_len = getstr(b, j.transaction_id, D2KU_ID_MAX);
        j.phase = (d2ku_phase)getnum(b, 4);
        j.failure_reason = (d2ku_rc)getnum(b, 4);
        j.recovery_reason = (d2ku_rc)getnum(b, 4);
        j.old_release_id_len = getstr(b, j.old_release_id, D2KU_ID_MAX);
        j.new_release_id_len = getstr(b, j.new_release_id, D2KU_ID_MAX);
        getbytes(b, j.old_manifest_sha256, 32); getbytes(b, j.new_manifest_sha256, 32);
        j.snapshot_ready = (int)getnum(b, 1); j.active_services = getnum(b, 8);
        j.progress_mono_ms = getnum(b, 8); uint64_t utc = getnum(b, 8);
        if (utc > INT64_MAX) b->bad = 1; else j.progress_utc = (int64_t)utc;
        j.progress_boot_id_len = getstr(b, j.progress_boot_id, D2KU_BOOT_ID_MAX);
        if (b->bad || b->pos != b->n || journal_valid(&j) != D2KU_OK) return D2KU_RECOVERY;
        *(d2ku_journal *)out = j;
    } else {
        d2ku_persistent_state s = {0}; s.schema = 1; s.sequence = seq; memcpy(s.checksum, saved, 32);
        s.accepted_sequence = getnum(b, 8); getbytes(b, s.accepted_index_sha256, 32);
        s.has_accepted_index = (int)getnum(b, 1); uint64_t utc = getnum(b, 8);
        if (utc > INT64_MAX) b->bad = 1; else s.last_accepted_timestamp = (int64_t)utc;
        s.trust_count = (size_t)getnum(b, 1); if (s.trust_count > D2KU_KEYS_MAX) return D2KU_RECOVERY;
        for (size_t i = 0; i < s.trust_count; i++) {
            getbytes(b, s.trust[i].public_key, 32); uint64_t start = getnum(b, 8), end = getnum(b, 8);
            if (start > INT64_MAX || end > INT64_MAX) b->bad = 1;
            else { s.trust[i].not_before = (int64_t)start; s.trust[i].not_after = (int64_t)end; }
        }
        s.policy.enabled = (int)getnum(b, 1);
        uint64_t selected = getnum(b, 4), attempt = getnum(b, 4);
        if (selected > INT32_MAX || attempt > INT32_MAX) b->bad = 1;
        else { s.policy.selected_date = (int32_t)selected; s.policy.last_attempt_date = (int32_t)attempt; }
        s.policy.selected_minute = (unsigned)getnum(b, 2);
        s.policy.has_quarantined_release = (int)getnum(b, 1);
        getbytes(b, s.policy.quarantined_release_sha256, 32);
        getstr(b, s.auto_operation, D2KU_ID_MAX);
        getstr(b, s.auto_release, D2KU_ID_MAX);
        getbytes(b, s.auto_manifest_sha256, 32);
        if (b->bad || b->pos != b->n || persistent_valid(&s) != D2KU_OK) return D2KU_RECOVERY;
        *(d2ku_persistent_state *)out = s;
    }
    return D2KU_OK;
}
static d2ku_rc syncfd(d2ku_ctx *c, int fd)
{
    if (c->sync_fd) return c->sync_fd(c->io_arg, fd);
    int rc; do { rc = fsync(fd); } while (rc < 0 && errno == EINTR);
    return rc == 0 ? D2KU_OK : D2KU_IO;
}
static int statfd(d2ku_ctx *c, int fd, struct stat *out)
{ return c->stat_fd ? c->stat_fd(c->io_arg, fd, out) : fstat(fd, out); }
static int owned(const struct stat *s, int dir)
{
    return (dir ? S_ISDIR(s->st_mode) : S_ISREG(s->st_mode)) &&
        s->st_uid == geteuid() && (s->st_mode & 077) == 0 && (dir || s->st_nlink == 1);
}
static d2ku_rc directory(d2ku_ctx *c, int create, int *out)
{
    if (!c || c->root_dirfd < 0) return D2KU_INVALID;
    int made = 0;
    if (create) {
        if (mkdirat(c->root_dirfd, "update-state", 0700) == 0) made = 1;
        else if (errno != EEXIST) return D2KU_IO;
    }
    int fd = openat(c->root_dirfd, "update-state", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
    struct stat st;
    if (statfd(c, fd, &st) < 0) { close(fd); return D2KU_IO; }
    if (!owned(&st, 1)) { close(fd); return D2KU_IO; }
    /* Re-sync parent on every create path, including retry after mkdir/fsync failure. */
    if (create && (syncfd(c, c->root_dirfd) != D2KU_OK || (made && syncfd(c, fd) != D2KU_OK))) {
        close(fd); return D2KU_IO;
    }
    *out = fd; return D2KU_OK;
}
static d2ku_rc lockat(d2ku_ctx *c, int dir, const char *name, int *out)
{
    int fd = openat(dir, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return D2KU_IO;
    struct stat st;
    if (statfd(c, fd, &st) < 0) { close(fd); return D2KU_IO; }
    if (!owned(&st, 0)) { close(fd); return D2KU_IO; }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        int busy = errno == EWOULDBLOCK || errno == EAGAIN; close(fd);
        return busy ? D2KU_BUSY : D2KU_IO;
    }
    *out = fd; return D2KU_OK;
}
static void filename(kind k, unsigned slot, char name[32])
{
    (void)snprintf(name, 32, "%s.%u", k == JOURNAL ? "journal" : "persistent", slot);
}
static d2ku_rc readslot(d2ku_ctx *c, int dir, kind k, unsigned slot, buffer *b, void *out)
{
    char name[32]; filename(k, slot, name);
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? D2KU_ABSENT : D2KU_IO;
    struct stat s;
    if (statfd(c, fd, &s) < 0) { close(fd); return D2KU_IO; }
    if (!owned(&s, 0) || s.st_size < 0 || (uint64_t)s.st_size > RECORD_MAX) {
        close(fd); return D2KU_RECOVERY;
    }
    memset(b, 0, sizeof *b);
    while (b->n < sizeof(b->b)) {
        ssize_t n = read(fd, b->b + b->n, sizeof(b->b) - b->n);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { close(fd); return D2KU_IO; }
        if (!n) break;
        b->n += (size_t)n;
    }
    close(fd); return decode(k, b, slot, out);
}
typedef union { d2ku_journal j; d2ku_persistent_state p; } record_union;
static uint64_t sequence(kind k, const record_union *r) { return k == JOURNAL ? r->j.sequence : r->p.sequence; }
static d2ku_rc loadat(d2ku_ctx *c, int dir, kind k, record_union *out, buffer *raw)
{
    record_union a, b; buffer ba, bb;
    d2ku_rc ra = readslot(c, dir, k, 0, &ba, &a), rb = readslot(c, dir, k, 1, &bb, &b);
    if (ra == D2KU_IO || rb == D2KU_IO) return D2KU_IO;
    if (ra != D2KU_OK && rb != D2KU_OK)
        return ra == D2KU_ABSENT && rb == D2KU_ABSENT ? D2KU_ABSENT : D2KU_RECOVERY;
    if (rb == D2KU_OK && (ra != D2KU_OK || sequence(k, &b) > sequence(k, &a))) { *out = b; *raw = bb; }
    else { *out = a; *raw = ba; }
    return D2KU_OK;
}
static d2ku_rc load(d2ku_ctx *c, kind k, record_union *r)
{
    int d; d2ku_rc rc = directory(c, 0, &d); if (rc != D2KU_OK) return rc;
    buffer raw; rc = loadat(c, d, k, r, &raw); close(d); return rc;
}
static int trust_progress(const d2ku_persistent_state *old, const d2ku_persistent_state *s)
{
    if (s->accepted_sequence < old->accepted_sequence || s->last_accepted_timestamp < old->last_accepted_timestamp ||
        s->policy.selected_date < old->policy.selected_date || s->policy.last_attempt_date < old->policy.last_attempt_date ||
        (old->has_accepted_index && (!s->has_accepted_index ||
            (s->accepted_sequence == old->accepted_sequence && memcmp(s->accepted_index_sha256, old->accepted_index_sha256, 32)))) ||
        (old->policy.selected_date && old->policy.selected_date == s->policy.selected_date &&
            old->policy.selected_minute != s->policy.selected_minute)) return 0;
    if (old->auto_operation[0] &&
        old->policy.last_attempt_date == s->policy.last_attempt_date &&
        (strcmp(old->auto_operation, s->auto_operation) ||
         strcmp(old->auto_release, s->auto_release) ||
         memcmp(old->auto_manifest_sha256, s->auto_manifest_sha256, 32)))
      return 0;
    for (size_t i = 0; i < old->trust_count; i++) {
        int found = 0;
        for (size_t j = 0; j < s->trust_count; j++)
            if (!memcmp(old->trust[i].public_key, s->trust[j].public_key, 32) &&
                old->trust[i].not_before == s->trust[j].not_before && old->trust[i].not_after == s->trust[j].not_after) found = 1;
        if (!found) return 0;
    }
    return 1;
}
static d2ku_rc writeall(d2ku_ctx *c, int fd, const buffer *b)
{
    size_t done = 0;
    while (done < b->n) {
        ssize_t n = c->write_fd ? c->write_fd(c->io_arg, fd, b->b + done, b->n - done) : write(fd, b->b + done, b->n - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || (size_t)n > b->n - done) return D2KU_IO;
        done += (size_t)n;
    }
    return D2KU_OK;
}
static d2ku_rc store(d2ku_ctx *c, kind k, const void *value, uint64_t seq)
{
    if (!c || !value) return D2KU_INVALID;
    buffer bytes; d2ku_rc rc = encode(k, value, &bytes); if (rc != D2KU_OK) return rc;
    int dir, lock = -1, fd = -1; char temp[64] = {0}, target[32]; int own_temp = 0;
    rc = directory(c, 1, &dir); if (rc != D2KU_OK) return rc;
    rc = lockat(c, dir, k == JOURNAL ? "journal.lock" : "persistent.lock", &lock);
    if (rc != D2KU_OK) { close(dir); return rc; }
    record_union old; buffer raw;
    rc = loadat(c, dir, k, &old, &raw);
    if (rc == D2KU_OK) {
        uint64_t previous = sequence(k, &old);
        if (seq == previous) {
            if (bytes.n != raw.n || memcmp(bytes.b, raw.b, raw.n)) { rc = D2KU_REPLAY; goto end; }
            /* A failed directory fsync may leave a visible generation. Exact
             * retry cannot just return OK: re-sync that inode and its directory. */
            filename(k, (unsigned)(seq%2), target);
            fd = openat(dir, target, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            rc = fd >= 0 && syncfd(c, fd) == D2KU_OK && syncfd(c, dir) == D2KU_OK ? D2KU_OK : D2KU_IO;
            goto end;
        }
        if (previous == UINT64_MAX || seq != previous + 1 ||
            (k == PERSISTENT && !trust_progress(&old.p, value))) { rc = D2KU_REPLAY; goto end; }
    } else if (rc == D2KU_ABSENT) {
        if (seq != 1) { rc = D2KU_REPLAY; goto end; }
    } else goto end;
    /* O_EXCL means collisions/foreign temporary files are never overwritten.
     * Never sweep leftovers: only unlink the exact temp created by this call. */
    for (unsigned i = 0; i < 1024; i++) {
        (void)snprintf(temp, sizeof temp, ".%s-%ld-%u", k == JOURNAL ? "journal" : "persistent", (long)getpid(), i);
        fd = openat(dir, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) { own_temp = 1; break; }
        if (errno != EEXIST) break;
    }
    if (fd < 0) { rc = D2KU_IO; goto end; }
    rc = writeall(c, fd, &bytes); if (rc != D2KU_OK) goto end;
    rc = syncfd(c, fd); if (rc != D2KU_OK) goto end;
    if (close(fd) < 0) { fd = -1; rc = D2KU_IO; goto end; } fd = -1;
    filename(k, (unsigned)(seq%2), target);
    rc = c->rename_at ? c->rename_at(c->io_arg, dir, temp, dir, target) :
        (renameat(dir, temp, dir, target) == 0 ? D2KU_OK : D2KU_IO);
    if (rc != D2KU_OK) goto end;
    own_temp = 0; rc = syncfd(c, dir);
end:
    if (fd >= 0) close(fd);
    if (own_temp) unlinkat(dir, temp, 0);
    close(lock); close(dir); return rc;
}
d2ku_rc d2ku_journal_load(d2ku_ctx *c, d2ku_journal *out)
{
    if (!out) return D2KU_INVALID;
    record_union r; d2ku_rc rc = load(c, JOURNAL, &r); if (rc == D2KU_OK) *out = r.j; return rc;
}
d2ku_rc d2ku_journal_store(d2ku_ctx *c, const d2ku_journal *j)
{ return j ? store(c, JOURNAL, j, j->sequence) : D2KU_INVALID; }
d2ku_rc d2ku_persistent_load(d2ku_ctx *c, d2ku_persistent_state *out)
{
    if (!out) return D2KU_INVALID;
    record_union r; d2ku_rc rc = load(c, PERSISTENT, &r); if (rc == D2KU_OK) *out = r.p; return rc;
}
d2ku_rc d2ku_persistent_store(d2ku_ctx *c, const d2ku_persistent_state *s)
{ return s ? store(c, PERSISTENT, s, s->sequence) : D2KU_INVALID; }
d2ku_rc d2ku_maintenance_lock(d2ku_ctx *c, int *out)
{
    if (!out) return D2KU_INVALID;
    int d; d2ku_rc rc = directory(c, 1, &d); if (rc != D2KU_OK) return rc;
    rc = lockat(c, d, "maintenance.lock", out); close(d); return rc;
}
void d2ku_maintenance_unlock(int fd) { if (fd >= 0) close(fd); }
