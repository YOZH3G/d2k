#include <stdlib.h>
#include <string.h>

#include "d2k_udp_hold.h"

typedef struct {
    int used;
    d2k_key key;
    uint64_t deadline;
    size_t count;
    uint32_t ids[D2K_UDP_HOLD_PACKETS];
    size_t len[D2K_UDP_HOLD_PACKETS];
    uint8_t packets[D2K_UDP_HOLD_PACKETS][D2K_UDP_HOLD_PACKET];
} udp_slot;

struct d2k_udp_hold { udp_slot slots[D2K_UDP_HOLD_SLOTS]; };

static int same_key(const d2k_key *a, const d2k_key *b) {
    return d2k_key_equal(a, b);
}

static void clear_slot(udp_slot *s) {
    memset(s, 0, sizeof *s);
}

static size_t release_slot(udp_slot *s, d2k_hold_release release, void *ctx) {
    size_t n = 0;
    if (release) {
        for (size_t i = 0; i < s->count; i++) {
            release(ctx, s->ids[i], s->packets[i], s->len[i]);
            n++;
        }
    }
    clear_slot(s);
    return n;
}

d2k_udp_hold *d2k_udp_hold_new(void) { return calloc(1, sizeof(d2k_udp_hold)); }

void d2k_udp_hold_free(d2k_udp_hold *h, d2k_hold_release release, void *ctx) {
    if (!h) { return; }
    for (size_t i = 0; i < D2K_UDP_HOLD_SLOTS; i++) {
        if (h->slots[i].used) { (void)release_slot(&h->slots[i], release, ctx); }
    }
    free(h);
}

size_t d2k_udp_hold_flush(d2k_udp_hold *h, uint64_t now_ns,
                          d2k_hold_release release, void *ctx) {
    size_t n = 0;
    if (!h) { return 0; }
    for (size_t i = 0; i < D2K_UDP_HOLD_SLOTS; i++) {
        udp_slot *s = &h->slots[i];
        if (s->used && now_ns >= s->deadline) {
            n += release_slot(s, release, ctx);
        }
    }
    return n;
}

int d2k_udp_hold_feed(d2k_udp_hold *h, const d2k_key *key, uint32_t id,
                      const uint8_t *packet, size_t len, uint64_t now_ns,
                      d2k_hold_release release, void *ctx) {
    if (!h || !key || !packet || len == 0 || len > D2K_UDP_HOLD_PACKET) {
        return 0;
    }
    (void)d2k_udp_hold_flush(h, now_ns, release, ctx);
    udp_slot *slot = NULL, *free_slot = NULL;
    for (size_t i = 0; i < D2K_UDP_HOLD_SLOTS; i++) {
        udp_slot *s = &h->slots[i];
        if (s->used && same_key(&s->key, key)) { slot = s; break; }
        if (!s->used && !free_slot) { free_slot = s; }
    }
    if (!slot) {
        if (!free_slot) { return 0; }
        slot = free_slot;
        memset(slot, 0, sizeof *slot);
        slot->used = 1;
        slot->key = *key;
        slot->deadline = now_ns + D2K_UDP_HOLD_WAIT_NS;
    }
    if (slot->count >= D2K_UDP_HOLD_PACKETS) {
        /* The caller will end the session hold when feed() returns 0.  Do not
           leave the IDs already owned by this slot behind that transition:
           they would otherwise remain pending until the deadline while the
           flow is already processing packets normally.  Release the complete
           batch immediately and let the caller retain the overflowing packet. */
        (void)release_slot(slot, release, ctx);
        return 0;
    }
    size_t i = slot->count++;
    slot->ids[i] = id;
    slot->len[i] = len;
    memcpy(slot->packets[i], packet, len);
    return 1;
}

int d2k_udp_hold_take(d2k_udp_hold *h, const d2k_key *key, uint64_t now_ns,
                      d2k_udp_hold_batch *out) {
    if (!h || !key || !out) { return 0; }
    /* Expiry must be flushed by the caller with its release callback.  Never
       clear an expired slot here without releasing its NFQUEUE IDs. */
    (void)now_ns;
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < D2K_UDP_HOLD_SLOTS; i++) {
        udp_slot *s = &h->slots[i];
        if (!s->used || !same_key(&s->key, key)) { continue; }
        out->key = s->key;
        out->count = s->count;
        memcpy(out->ids, s->ids, sizeof out->ids);
        memcpy(out->len, s->len, sizeof out->len);
        memcpy(out->packets, s->packets, sizeof out->packets);
        clear_slot(s);
        return 1;
    }
    return 0;
}
