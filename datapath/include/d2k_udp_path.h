/* d2k_udp_path.h — the service's split-QUIC hold around one session call.
 *
 * d2kd does, for each queued packet: pre (start/feed the hold), the session
 * call, post (held / replay / reclaimed / normal).  The steps live here, not
 * inline in d2kd.c, so that NFQUEUE-ID ownership can be tested without the
 * Linux sockets (task 46, review M4): every ID gets exactly one verdict.
 */
#ifndef D2K_UDP_PATH_H
#define D2K_UDP_PATH_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_session.h"
#include "d2k_udp_hold.h"
#include "d2k_udp_release.h"

typedef struct {
    d2k_session *sess;
    d2k_udp_hold *hold;
    const d2k_udp_out *out;
    uint64_t now_ns;   /* set by the caller before d2k_udp_hold_flush */
    uint64_t seq;      /* receive batch of the packets now being read */
} d2k_udp_path;

enum {
    D2K_UDP_PATH_NORMAL = 0,  /* caller issues the verdict for its packet */
    D2K_UDP_PATH_HELD,        /* the hold owns the ID; nothing to do */
    D2K_UDP_PATH_REPLAY,      /* *batch taken: plan the head, release with out */
    D2K_UDP_PATH_RECLAIMED,   /* the slot (with this ID) was released here */
    D2K_UDP_PATH_LOST         /* ready, but the slot is gone: normal verdict */
};

/* d2k_udp_hold_release callback (ctx = d2k_udp_path *): closes the session's
 * hold transaction and releases the slot through out, head first. */
void d2k_udp_path_release(void *ctx, const d2k_udp_hold_batch *b);

/* Starts or feeds the hold.  Returns 1 when the hold now owns id. */
int d2k_udp_path_pre(d2k_udp_path *pp, uint32_t id, const uint8_t *pkt,
                     size_t len, uint64_t now_ns, d2k_key *key);

/* Decides after the session call.  fed is pre()'s answer.
 *
 * A packet the hold took but the session neither held nor declared ready
 * (an early exit before its hold block) is not left in the slot: the slot is
 * taken back and released now, this ID included (review I1).  Otherwise the
 * caller would ACCEPT the ID while the slot still owned it, and the expiry
 * would verdict it again and re-send datagrams already on the wire. */
int d2k_udp_path_post(d2k_udp_path *pp, int fed, const d2k_key *key,
                      const d2k_result *res, d2k_udp_hold_batch *batch);

#endif
