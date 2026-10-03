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
                     size_t len, uint32_t mark, uint64_t now_ns, d2k_key *key) {
    if (!pp || !pp->hold || !key) { return 0; }
    pp->now_ns = now_ns;
    /* Expired slots go first (review N1).  Otherwise feed() would expire this
       flow's own slot after hold_begin, its release would end the session's
       hold, and the session would apply a plan to a packet the new slot
       owns: reclaimed as a plain ACCEPT, the plan recorded with nothing on
       the wire.  Flushed here, begin opens a fresh hold and the session says
       ready: the plan goes through the replay path. */
    (void)d2k_udp_hold_flush(pp->hold, now_ns, d2k_udp_path_release, pp);
    if (!d2k_session_udp_hold_begin(pp->sess, pkt, len, now_ns, key)) { return 0; }
    if (!d2k_udp_hold_feed_marked(pp->hold, key, id, pkt, len, mark, now_ns,
                                  d2k_udp_path_release, pp)) {
        d2k_session_udp_hold_end(pp->sess, key);
        return 0;
    }
    return 1;
}

int d2k_udp_path_post(d2k_udp_path *pp, int fed, const d2k_key *key,
                      const d2k_result *res, d2k_udp_hold_batch *batch) {
    if (!pp || !res) { return D2K_UDP_PATH_NORMAL; }
    /* Only an ID the hold took is held; a wait for anything else (e.g. a
       first IPv4 fragment hold_begin refused) keeps the caller's verdict
       (review N4). */
    if (res->udp_hold_wait) { return fed ? D2K_UDP_PATH_HELD : D2K_UDP_PATH_NORMAL; }
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

void d2k_udp_path_read(d2k_udp_path *pp, uint64_t now_ns) {
    if (!pp) { return; }
    pp->rseq++;
    pp->seq = pp->rseq;
    pp->now_ns = now_ns;
}

size_t d2k_udp_path_expire(d2k_udp_path *pp, uint64_t now_ns, int read_follows) {
    if (!pp || !pp->hold) { return 0; }
    pp->now_ns = now_ns;
    pp->seq = read_follows ? pp->rseq + 1 : D2K_UDP_SEQ_NONE;
    return d2k_udp_hold_flush(pp->hold, now_ns, d2k_udp_path_release, pp);
}

int d2k_udp_path_passed(d2k_udp_path *pp, const uint8_t *pkt, size_t len,
                        uint32_t mark, uint64_t now_ns) {
    if (!pp || !pp->out || !pp->out->can_resend || !pp->out->follow ||
        !pkt || len < 20 || (pkt[0] >> 4) != 4 ||
        !d2k_session_udp_opening(pp->sess, pkt, len)) {
        return 0;
    }
    if (!d2k_udp_out_neutral(pp->out, mark)) {
        if (pp->out->marked) { pp->out->marked(pp->out->ctx, pkt, len, mark); }
        return 0;
    }
    return d2k_udp_follow_mark(pp->out->follow, pkt, len, now_ns, 0, pp->seq) == 0;
}

int d2k_udp_path_planned(d2k_udp_path *pp, const uint8_t *pkt, size_t len,
                         uint32_t mark, uint64_t at_ns, uint64_t now_ns) {
    if (!pp || !pp->out || !pp->out->can_resend || !pp->out->follow ||
        !pkt || len < 20 || (pkt[0] >> 4) != 4 || !d2k_udp_out_neutral(pp->out, mark)) {
        return 0;
    }
    return d2k_udp_follow_mark(pp->out->follow, pkt, len, now_ns, at_ns, pp->seq) == 0;
}
