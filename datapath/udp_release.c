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

typedef struct {
    int (*fn)(void *ctx, uint64_t at_ns, uint32_t id, uint32_t verdict);
    void *ctx;
    uint64_t at_ns;
} defer_op;

static size_t release_batch(const d2k_udp_hold_batch *b, uint32_t head_verdict,
                            int owned, int can_resend, const uint8_t *may,
                            const defer_op *defer,
                            d2k_udp_release_send verdict, d2k_udp_resend resend,
                            void *ctx, int *verdict_failed, size_t *resend_failed);

size_t d2k_udp_release_batch(const d2k_udp_hold_batch *b, uint32_t head_verdict,
                             int owned, int can_resend,
                             d2k_udp_release_send verdict, d2k_udp_resend resend,
                             void *ctx, int *verdict_failed, size_t *resend_failed) {
    return release_batch(b, head_verdict, owned, can_resend, NULL, NULL, verdict, resend,
                         ctx, verdict_failed, resend_failed);
}

static size_t release_batch(const d2k_udp_hold_batch *b, uint32_t head_verdict,
                            int owned, int can_resend, const uint8_t *may,
                            const defer_op *defer,
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
        if (again[i] && vfail && !owned) {
            /* The head's verdict did not reach the kernel: it is still queued
               and its entry unconfirmed.  A raw tail now would overtake it
               and create the entry itself (review M2). */
            again[i] = 0;
            v[i] = D2K_NF_ACCEPT;
            fell_back++;
        }
        if (again[i] && may && !may[i]) {
            /* Marked client: its policy route must hold; the kernel path —
               but never ahead of a deferred head (rereview4 I3). */
            again[i] = 0;
            v[i] = D2K_NF_ACCEPT;
            if (defer && defer->fn) {
                if (defer->fn(defer->ctx, defer->at_ns, b->ids[i], v[i]) != 0) { vfail = 1; }
                continue;
            }
        }
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
    uint64_t at_ns;
    uint64_t seq;
    uint8_t used;
    uint8_t noted;     /* a marked follower of this flow was reported */
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

static follow_entry *follow_put(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                                uint64_t now_ns, uint64_t at_ns, uint64_t seq);

int d2k_udp_follow_mark(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                        uint64_t now_ns, uint64_t at_ns, uint64_t seq) {
    return follow_put(f, pkt, len, now_ns, at_ns, seq) ? 0 : -1;
}

static follow_entry *follow_put(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                                uint64_t now_ns, uint64_t at_ns, uint64_t seq) {
    follow_entry t;
    if (!f || follow_tuple(pkt, len, &t) != 0) { return NULL; }
    uint64_t out = at_ns > now_ns ? at_ns : now_ns;
    t.until_ns = out + D2K_UDP_FOLLOW_NS;
    t.at_ns = at_ns > now_ns ? at_ns : 0;
    t.seq = seq;
    t.used = 1;
    follow_entry *slot = NULL, *spare = NULL;
    for (size_t i = 0; i < D2K_UDP_FOLLOW_SLOTS && !slot; i++) {
        follow_entry *e = &f->e[i];
        if (e->used && same_tuple(e, &t)) { slot = e; }
        else if (!spare || (spare->used && (!e->used || e->until_ns < spare->until_ns))) {
            spare = e;
        }
    }
    follow_entry *e = slot ? slot : spare;
    *e = t;
    return e;
}

int d2k_udp_follow_match(const d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                         uint64_t now_ns, uint64_t seq, uint64_t *at_ns) {
    follow_entry t;
    if (!f || follow_tuple(pkt, len, &t) != 0) { return 0; }
    for (size_t i = 0; i < D2K_UDP_FOLLOW_SLOTS; i++) {
        const follow_entry *e = &f->e[i];
        if (!e->used || !same_tuple(e, &t)) { continue; }
        if ((e->seq && e->seq == seq) || now_ns < e->until_ns) {
            if (at_ns) { *at_ns = e->at_ns; }
            return 1;
        }
    }
    return 0;
}

typedef struct {
    const d2k_udp_out *o;
    uint64_t at, now;
} out_tail;

static int out_resend(void *ctx, const uint8_t *pkt, size_t len) {
    out_tail *c = ctx;
    if (c->at > c->now) {
        return c->o->send_at ? c->o->send_at(c->o->ctx, c->at, pkt, len) : -1;
    }
    return c->o->send_now ? c->o->send_now(c->o->ctx, pkt, len) : -1;
}

static int out_verdict(void *ctx, uint32_t id, uint32_t verdict) {
    out_tail *c = ctx;
    return c->o->verdict(c->o->ctx, id, verdict);
}

int d2k_udp_out_neutral(const d2k_udp_out *o, uint32_t mark, uint8_t ipver) {
    if (mark == 0 || (o && o->neutral_mark && mark == o->neutral_mark)) { return 1; }
    return o && o->routed && !o->routed(o->routes, ipver, mark);
}

int d2k_udp_out_batch(const d2k_udp_out *o, const d2k_udp_hold_batch *b,
                      uint32_t head_verdict, int owned,
                      uint64_t at_ns, uint64_t now_ns, uint64_t seq) {
    if (!o || !o->verdict || !b || !b->count || b->count > D2K_UDP_HOLD_PACKETS) { return 0; }
    out_tail c = {o, at_ns, now_ns};
    int can = o->can_resend && o->send_now;
    int vfail = 0;
    size_t rfail = 0;
    uint8_t may[D2K_UDP_HOLD_PACKETS];
    int marked_tail = 0;
    for (size_t i = 0; i < b->count; i++) {
        may[i] = (uint8_t)d2k_udp_out_neutral(o, b->marks[i], (uint8_t)(b->packets[i][0] >> 4));
        if (i > 0 && !may[i]) { marked_tail = 1; }
    }
    defer_op d = {o->defer_verdict, o->ctx, at_ns};
    (void)release_batch(b, head_verdict, can ? owned : 0, can, may,
                        (at_ns > now_ns && o->defer_verdict) ? &d : NULL, out_verdict,
                        can ? out_resend : NULL, &c, &vfail, &rfail);
    if (can && marked_tail && o->marked) {
        size_t i = 1;
        while (i < b->count && may[i]) { i++; }
        o->marked(o->ctx, b->packets[i], b->len[i], b->marks[i]);
    }
    if (can && o->follow && may[0]) {
        follow_entry *e = follow_put(o->follow, b->packets[0], b->len[0], now_ns, at_ns, seq);
        /* Counted once per flow, batch or late datagram (rereview4 N9). */
        if (e && marked_tail) { e->noted = 1; }
    }
    return vfail;
}

static follow_entry *follow_find(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                                 uint64_t now_ns, uint64_t seq) {
    follow_entry t;
    if (!f || follow_tuple(pkt, len, &t) != 0) { return NULL; }
    for (size_t i = 0; i < D2K_UDP_FOLLOW_SLOTS; i++) {
        follow_entry *e = &f->e[i];
        if (!e->used || !same_tuple(e, &t)) { continue; }
        if ((e->seq && e->seq == seq) || now_ns < e->until_ns) { return e; }
    }
    return NULL;
}

int d2k_udp_out_late(const d2k_udp_out *o, uint32_t id, const uint8_t *pkt,
                     size_t len, uint32_t mark, uint64_t now_ns, uint64_t seq,
                     int *verdict_failed) {
    if (!o || !o->verdict || !o->can_resend || !o->send_now || !o->follow) { return 0; }
    follow_entry *e = follow_find(o->follow, pkt, len, now_ns, seq);
    if (!e) { return 0; }
    if (!d2k_udp_out_neutral(o, mark, (uint8_t)(pkt[0] >> 4))) {
        if (!e->noted && o->marked) { o->marked(o->ctx, pkt, len, mark); }
        e->noted = 1;
        if (e->at_ns && o->defer_verdict) {
            /* Behind a deferred planned head: ACCEPT, but not before it
               leaves (rereview4 I3). */
            int rc = o->defer_verdict(o->ctx, e->at_ns, id, D2K_NF_ACCEPT);
            if (verdict_failed) { *verdict_failed = rc != 0; }
            return 1;
        }
        return 0;  /* the caller's ordinary ACCEPT */
    }
    /* A deferred head stays deferred until the queue pops it, even once due:
       queue the tail at its time whenever there is one (review N3). */
    out_tail c = {o, e->at_ns, e->at_ns ? 0 : now_ns};
    uint32_t v = out_resend(&c, pkt, len) == 0 ? D2K_NF_DROP : D2K_NF_ACCEPT;
    int rc = o->verdict(o->ctx, id, v);
    if (verdict_failed) { *verdict_failed = rc != 0; }
    return 1;
}
