#include <stdlib.h>
#include <string.h>

#include "d2k_udp_release.h"
#include "d2k_nl.h"
#include "d2k_packet.h"

typedef struct {
    int used;
    uint64_t due_ns;
    uint64_t seq;
    uint64_t token;
    d2k_key key;
    size_t count;
    uint32_t *ids;
    uint32_t *verdicts;
} release_slot;

struct d2k_udp_release {
    size_t slots;
    size_t batch_size;
    uint64_t next_seq;
    release_slot *slot;
    uint32_t *ids;
    uint32_t *verdicts;
};

d2k_udp_release *d2k_udp_release_new(size_t slots, size_t batch_size) {
    if (slots == 0 || batch_size == 0 ||
        slots > (size_t)-1 / batch_size) {
        return NULL;
    }
    d2k_udp_release *q = calloc(1, sizeof *q);
    if (!q) return NULL;
    size_t n = slots * batch_size;
    q->slots = slots;
    q->batch_size = batch_size;
    q->slot = calloc(slots, sizeof *q->slot);
    q->ids = calloc(n, sizeof *q->ids);
    q->verdicts = calloc(n, sizeof *q->verdicts);
    if (!q->slot || !q->ids || !q->verdicts) {
        d2k_udp_release_free(q);
        return NULL;
    }
    for (size_t i = 0; i < slots; i++) {
        q->slot[i].ids = q->ids + i * batch_size;
        q->slot[i].verdicts = q->verdicts + i * batch_size;
    }
    return q;
}

void d2k_udp_release_free(d2k_udp_release *q) {
    if (!q) return;
    free(q->verdicts);
    free(q->ids);
    free(q->slot);
    free(q);
}

int d2k_udp_release_enqueue(d2k_udp_release *q, uint64_t due_ns,
                            const uint32_t *ids, const uint32_t *verdicts,
                            size_t count, const d2k_key *key, uint64_t token) {
    if (!q || !ids || !verdicts || !key || count == 0 || count > q->batch_size) {
        return -1;
    }
    release_slot *free_slot = NULL;
    for (size_t i = 0; i < q->slots; i++) {
        if (!q->slot[i].used) { free_slot = &q->slot[i]; break; }
    }
    if (!free_slot) return -1;
    memcpy(free_slot->ids, ids, count * sizeof *ids);
    memcpy(free_slot->verdicts, verdicts, count * sizeof *verdicts);
    free_slot->used = 1;
    free_slot->due_ns = due_ns;
    free_slot->seq = q->next_seq++;
    free_slot->key = *key;
    free_slot->token = token;
    free_slot->count = count;
    return 0;
}

static release_slot *next_due(d2k_udp_release *q, uint64_t now_ns) {
    release_slot *best = NULL;
    for (size_t i = 0; i < q->slots; i++) {
        release_slot *s = &q->slot[i];
        if (!s->used || s->due_ns > now_ns) continue;
        if (!best || s->due_ns < best->due_ns ||
            (s->due_ns == best->due_ns && s->seq < best->seq)) {
            best = s;
        }
    }
    return best;
}

size_t d2k_udp_release_flush(d2k_udp_release *q, uint64_t now_ns,
                             d2k_udp_release_send send, d2k_udp_release_done done,
                             void *ctx) {
    size_t released = 0;
    if (!q) return 0;
    for (;;) {
        release_slot *s = next_due(q, now_ns);
        if (!s) break;
        int complete = 1;
        uint64_t token = s->token;
        d2k_key key = s->key;
        size_t count = s->count;
        size_t sent = 0;
        for (size_t i = 0; i < count; i++) {
            if (!send || send(ctx, s->ids[i], s->verdicts[i]) != 0) {
                complete = 0;
            } else {
                sent++;
            }
        }
        s->used = 0;
        s->count = 0;
        if (done) done(ctx, &key, token, complete, sent);
        released++;
    }
    return released;
}

uint64_t d2k_udp_release_next_ns(const d2k_udp_release *q) {
    uint64_t next = 0;
    if (!q) return 0;
    for (size_t i = 0; i < q->slots; i++) {
        const release_slot *s = &q->slot[i];
        if (!s->used) continue;
        if (next == 0 || s->due_ns < next) next = s->due_ns;
    }
    return next;
}

size_t d2k_udp_replay_fates(size_t count, uint32_t head_verdict, int owned,
                            int can_resend, uint32_t *verdicts, uint8_t *resend) {
    size_t again = 0;
    if (owned) { can_resend = 1; }
    for (size_t i = 0; i < count; i++) {
        if (i == 0) {
            /* An owned head already left as the plan's last emit. */
            verdicts[i] = owned ? D2K_NF_DROP : head_verdict;
            resend[i] = 0;
        } else if (can_resend) {
            verdicts[i] = D2K_NF_DROP;
            resend[i] = 1;
            again++;
        } else {
            verdicts[i] = D2K_NF_ACCEPT;
            resend[i] = 0;
        }
    }
    return again;
}

size_t d2k_udp_release_batch(const d2k_udp_hold_batch *b, uint32_t head_verdict,
                             int owned, int can_resend,
                             d2k_udp_release_send verdict, d2k_udp_resend resend,
                             void *ctx, int *verdict_failed, size_t *resend_failed) {
    uint32_t v[D2K_UDP_HOLD_PACKETS];
    uint8_t again[D2K_UDP_HOLD_PACKETS];
    size_t resent = 0, fell_back = 0;
    int vfail = 0;
    if (!b || !verdict || b->count == 0 || b->count > D2K_UDP_HOLD_PACKETS) {
        if (verdict_failed) { *verdict_failed = b && b->count ? 1 : 0; }
        if (resend_failed) { *resend_failed = 0; }
        return 0;
    }
    if (!resend) { can_resend = 0; owned = 0; }
    (void)d2k_udp_replay_fates(b->count, head_verdict, owned, can_resend, v, again);
    for (size_t i = 0; i < b->count; i++) {
        if (again[i]) {
            if (resend(ctx, b->packets[i], b->len[i]) == 0) {
                resent++;
            } else {
                v[i] = D2K_NF_ACCEPT;
                fell_back++;
            }
        }
        if (verdict(ctx, b->ids[i], v[i]) != 0) { vfail = 1; }
    }
    if (verdict_failed) { *verdict_failed = vfail; }
    if (resend_failed) { *resend_failed = fell_back; }
    return resent;
}

typedef struct {
    uint64_t until_ns;
    uint8_t family;
    uint8_t src[16], dst[16];
    uint8_t ports[4];
} follow_entry;

struct d2k_udp_follow { follow_entry e[D2K_UDP_FOLLOW_SLOTS]; };

d2k_udp_follow *d2k_udp_follow_new(void) { return calloc(1, sizeof(d2k_udp_follow)); }

void d2k_udp_follow_free(d2k_udp_follow *f) { free(f); }

static int follow_tuple(const uint8_t *pkt, size_t len, follow_entry *out) {
    d2k_packet_view v;
    if (!d2k_packet_parse(pkt, len, &v) || v.protocol != 17) { return -1; }
    /* d2k_packet_parse refuses later fragments; the first one still parses.
       Neither is a whole datagram to re-send. */
    if (v.family == 4 && (v.fragment & 0x2000u)) { return -1; }
    memset(out, 0, sizeof *out);
    out->family = v.family;
    size_t alen = v.family == 6 ? 16 : 4;
    memcpy(out->src, v.src.bytes, alen);
    memcpy(out->dst, v.dst.bytes, alen);
    memcpy(out->ports, pkt + v.l4, 4);
    return 0;
}

static int same_tuple(const follow_entry *a, const follow_entry *b) {
    return a->family == b->family && !memcmp(a->src, b->src, sizeof a->src) &&
           !memcmp(a->dst, b->dst, sizeof a->dst) && !memcmp(a->ports, b->ports, 4);
}

int d2k_udp_follow_mark(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                        uint64_t now_ns) {
    follow_entry t;
    if (!f || follow_tuple(pkt, len, &t) != 0) { return -1; }
    t.until_ns = now_ns + D2K_UDP_FOLLOW_NS;
    follow_entry *slot = NULL;
    for (size_t i = 0; i < D2K_UDP_FOLLOW_SLOTS; i++) {
        follow_entry *e = &f->e[i];
        if (e->until_ns && same_tuple(e, &t)) { slot = e; break; }
        if (!slot || e->until_ns < slot->until_ns) { slot = e; }
    }
    *slot = t;
    return 0;
}

int d2k_udp_follow_match(const d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                         uint64_t now_ns) {
    follow_entry t;
    if (!f || follow_tuple(pkt, len, &t) != 0) { return 0; }
    for (size_t i = 0; i < D2K_UDP_FOLLOW_SLOTS; i++) {
        const follow_entry *e = &f->e[i];
        if (e->until_ns > now_ns && same_tuple(e, &t)) { return 1; }
    }
    return 0;
}
