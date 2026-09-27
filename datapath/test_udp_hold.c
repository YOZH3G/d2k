#include <stdio.h>
#include <string.h>

#include "d2k_udp_hold.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "udp_hold:%d: %s\n", __LINE__, m); fails++; } } while (0)

static size_t released;
static uint32_t released_ids[32];
static void release_one(void *ctx, uint32_t id, const uint8_t *p, size_t n) {
    (void)ctx; (void)p; CHECK(n > 0, "released packet has length");
    if (released < sizeof released_ids / sizeof released_ids[0]) released_ids[released] = id;
    released++;
}

int main(void) {
    d2k_udp_hold *h = d2k_udp_hold_new(); CHECK(h != NULL, "allocation");
    d2k_key k = {1,2,3,4,17};
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

    CHECK(d2k_udp_hold_feed(h, &k, 12, a, sizeof a, 200, release_one, NULL) == 1,
          "timeout candidate owned");
    CHECK(d2k_udp_hold_flush(h, 200 + D2K_UDP_HOLD_WAIT_NS, release_one, NULL) == 1,
          "expired datagram released");
    CHECK(released == 1 && released_ids[0] == 12, "timeout release exact ID");

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
    CHECK(released == 8, "overflow releases every previously-owned ID");
    CHECK(d2k_udp_hold_take(h, &k, 401, &out) == 0,
          "overflow leaves no stale hold slot");

    d2k_udp_hold_free(h, release_one, NULL);
    CHECK(fails == 0, "all UDP hold checks passed");
    if (!fails) puts("UDP hold: FIFO, bounds and timeout checks passed");
    return fails != 0;
}
