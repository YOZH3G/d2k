#include <stdlib.h>
#include <string.h>

#include "d2k_udp_release.h"

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
