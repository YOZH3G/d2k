#include <stdio.h>
#include <string.h>

#include "d2k_udp_hold.h"
#include "d2k_udp_release.h"
#include "d2k_nl.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "udp_hold:%d: %s\n", __LINE__, m); fails++; } } while (0)

static size_t released;
static uint32_t released_ids[32];
static size_t batches;
/* The hold hands back a whole slot at once, in arrival order (task 46): the
   caller must release the head before re-sending the tails. */
static void release_one(void *ctx, const d2k_udp_hold_batch *b) {
    (void)ctx;
    batches++;
    for (size_t i = 0; i < b->count; i++) {
        CHECK(b->len[i] > 0, "released packet has length");
        if (released < sizeof released_ids / sizeof released_ids[0]) released_ids[released] = b->ids[i];
        released++;
    }
}

/* Expiry through the real release order (task 46). */
static char ev_kind[16];
static uint32_t ev_id[16], ev_v[16];
static uint8_t ev_byte[16];
static size_t ev_n;
static int ev_verdict(void *ctx, uint32_t id, uint32_t v) {
    (void)ctx;
    if (ev_n < 16) { ev_kind[ev_n] = 'v'; ev_id[ev_n] = id; ev_v[ev_n] = v; }
    ev_n++;
    return 0;
}
static int ev_resend(void *ctx, const uint8_t *p, size_t n) {
    (void)ctx; (void)n;
    if (ev_n < 16) { ev_kind[ev_n] = 's'; ev_byte[ev_n] = p[0]; }
    ev_n++;
    return 0;
}
static void release_follow(void *ctx, const d2k_udp_hold_batch *b) {
    int vf = 0;
    size_t rf = 0;
    (void)d2k_udp_release_batch(b, D2K_NF_ACCEPT, 0, 1, ev_verdict, ev_resend, ctx, &vf, &rf);
}

int main(void) {
    d2k_udp_hold *h = d2k_udp_hold_new(); CHECK(h != NULL, "allocation");
    d2k_key k = {.low_ip=1, .high_ip=2, .low_port=3, .high_port=4, .proto=17};
    uint8_t a[3] = {1,2,3}, b[2] = {4,5};
    CHECK(d2k_udp_hold_feed(h, &k, 10, a, sizeof a, 100, release_one, NULL) == 1,
          "first datagram owned");
    CHECK(d2k_udp_hold_feed(h, &k, 11, b, sizeof b, 101, release_one, NULL) == 1,
          "second datagram owned");
    d2k_udp_hold_batch out;
    CHECK(d2k_udp_hold_take(h, &k, 102, &out) == 1 && out.count == 2,
          "take returns complete flow");
    CHECK(out.ids[0] == 10 && out.ids[1] == 11 && out.len[0] == 3 && out.len[1] == 2,
          "FIFO IDs and lengths preserved");
    CHECK(!memcmp(out.packets[0], a, sizeof a) && !memcmp(out.packets[1], b, sizeof b),
          "original datagrams preserved without concatenation");
    CHECK(d2k_udp_hold_take(h, &k, 103, &out) == 0, "taken flow removed");

    CHECK(d2k_udp_hold_next_ns(h) == 0, "empty table has no deadline");
    CHECK(d2k_udp_hold_feed(h, &k, 12, a, sizeof a, 200, release_one, NULL) == 1,
          "timeout candidate owned");
    /* The service sleeps until the earliest deadline; without it the expiry
       waited for the next unrelated packet or the 200 ms poll cap. */
    CHECK(d2k_udp_hold_next_ns(h) == 200 + D2K_UDP_HOLD_WAIT_NS,
          "hold deadline is exposed to the poll loop");
    CHECK(d2k_udp_hold_flush(h, 200 + D2K_UDP_HOLD_WAIT_NS - 1, release_one, NULL) == 0,
          "nothing released before the deadline");
    CHECK(d2k_udp_hold_flush(h, 200 + D2K_UDP_HOLD_WAIT_NS, release_one, NULL) == 1,
          "expired datagram released");
    CHECK(released == 1 && released_ids[0] == 12, "timeout release exact ID");
    CHECK(d2k_udp_hold_next_ns(h) == 0, "released slot has no deadline");

    /* Expiry of a 3-datagram slot: head ACCEPT first, then each tail re-sent
       in arrival order and its queued copy dropped (task 46). */
    {
        uint8_t x[3] = {0x71, 0, 0}, y[3] = {0x72, 0, 0}, z[3] = {0x73, 0, 0};
        CHECK(d2k_udp_hold_feed(h, &k, 30, x, sizeof x, 500, release_follow, NULL) == 1 &&
              d2k_udp_hold_feed(h, &k, 31, y, sizeof y, 501, release_follow, NULL) == 1 &&
              d2k_udp_hold_feed(h, &k, 32, z, sizeof z, 502, release_follow, NULL) == 1,
              "three datagrams held");
        ev_n = 0;
        CHECK(d2k_udp_hold_flush(h, 500 + D2K_UDP_HOLD_WAIT_NS, release_follow, NULL) == 3,
              "expiry releases all three IDs");
        CHECK(ev_n == 5, "one verdict per ID, one send per tail");
        CHECK(ev_kind[0] == 'v' && ev_id[0] == 30 && ev_v[0] == D2K_NF_ACCEPT,
              "expiry: head verdict first");
        CHECK(ev_kind[1] == 's' && ev_byte[1] == 0x72 && ev_kind[2] == 'v' &&
              ev_id[2] == 31 && ev_v[2] == D2K_NF_DROP,
              "expiry: first tail re-sent, then its copy dropped");
        CHECK(ev_kind[3] == 's' && ev_byte[3] == 0x73 && ev_kind[4] == 'v' &&
              ev_id[4] == 32 && ev_v[4] == D2K_NF_DROP,
              "expiry: second tail re-sent, then its copy dropped");
    }

    /* Overflow must fail closed: already-owned NFQUEUE IDs are released now,
       not left pending until the hold timeout after the caller ends hold. */
    released = 0;
    for (uint32_t id = 20; id < 28; id++) {
        CHECK(d2k_udp_hold_feed(h, &k, id, a, sizeof a, 300 + id,
                                release_one, NULL) == 1,
              "bounded slot accepts packet");
    }
    CHECK(d2k_udp_hold_feed(h, &k, 28, a, sizeof a, 400, release_one, NULL) == 0,
          "overflow is rejected");
    CHECK(released == 8 && batches > 0, "overflow releases every previously-owned ID");
    CHECK(d2k_udp_hold_take(h, &k, 401, &out) == 0,
          "overflow leaves no stale hold slot");

    d2k_udp_hold_free(h, release_one, NULL);
    CHECK(fails == 0, "all UDP hold checks passed");
    if (!fails) puts("UDP hold: FIFO, bounds and timeout checks passed");
    return fails != 0;
}
