#include <string.h>

#include "d2k_udp_path.h"
#include "d2k_nl.h"

void d2k_udp_path_release(void *ctx, const d2k_udp_hold_batch *b) {
    d2k_udp_path *pp = ctx;
    if (!pp || !b || !b->count) { return; }
    /* The hold transaction closes with the slot; otherwise the next packet on
       the same 5-tuple would be held against originals that are gone. */
    d2k_session_udp_hold_end(pp->sess, &b->key);
    (void)d2k_udp_out_batch(pp->out, b, D2K_NF_ACCEPT, 0, pp->now_ns, pp->now_ns, pp->seq);
}

int d2k_udp_path_pre(d2k_udp_path *pp, uint32_t id, const uint8_t *pkt,
                     size_t len, uint64_t now_ns, d2k_key *key) {
    if (!pp || !pp->hold || !key) { return 0; }
    pp->now_ns = now_ns;
    if (!d2k_session_udp_hold_begin(pp->sess, pkt, len, now_ns, key)) { return 0; }
    if (!d2k_udp_hold_feed(pp->hold, key, id, pkt, len, now_ns,
                           d2k_udp_path_release, pp)) {
        d2k_session_udp_hold_end(pp->sess, key);
        return 0;
    }
    return 1;
}

int d2k_udp_path_post(d2k_udp_path *pp, int fed, const d2k_key *key,
                      const d2k_result *res, d2k_udp_hold_batch *batch) {
    if (!pp || !res) { return D2K_UDP_PATH_NORMAL; }
    if (res->udp_hold_wait) { return D2K_UDP_PATH_HELD; }
    if (res->udp_hold_ready) {
        if (pp->hold && batch && d2k_udp_hold_take(pp->hold, key, pp->now_ns, batch) &&
            batch->count > 0) {
            d2k_session_udp_hold_replay(pp->sess, key);
            return D2K_UDP_PATH_REPLAY;
        }
        d2k_session_udp_hold_end(pp->sess, key);
        return D2K_UDP_PATH_LOST;
    }
    if (fed && pp->hold) {
        d2k_udp_hold_batch b;
        if (d2k_udp_hold_take(pp->hold, key, pp->now_ns, &b) && b.count > 0) {
            d2k_udp_path_release(pp, &b);
            return D2K_UDP_PATH_RECLAIMED;
        }
        d2k_session_udp_hold_end(pp->sess, key);
    }
    return D2K_UDP_PATH_NORMAL;
}
