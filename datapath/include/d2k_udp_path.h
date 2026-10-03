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
    uint64_t rseq;     /* last receive batch number handed out */
} d2k_udp_path;

/* No read ever gets this number (reads start at 1). */
#define D2K_UDP_SEQ_NONE 0

/* A new NFQUEUE receive batch is about to be processed. */
void d2k_udp_path_read(d2k_udp_path *pp, uint64_t now_ns);

/* Releases expired slots outside packet processing (the poll wake, a receive
 * error, shutdown).  Their datagrams' clash window is the next read only if a
 * read follows in this same loop pass (read_follows): what is queued now is
 * read then.  Otherwise the release gets D2K_UDP_SEQ_NONE, and a later read
 * matches by time only (review N2).  Returns released IDs. */
size_t d2k_udp_path_expire(d2k_udp_path *pp, uint64_t now_ns, int read_follows);

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
                     size_t len, uint32_t mark, uint64_t now_ns, d2k_key *key);

/* Decides after the session call.  fed is pre()'s answer.
 *
 * A packet the hold took but the session neither held nor declared ready
 * (an early exit before its hold block) is not left in the slot: the slot is
 * taken back and released now, this ID included (review I1).  Otherwise the
 * caller would ACCEPT the ID while the slot still owned it, and the expiry
 * would verdict it again and re-send datagrams already on the wire. */
int d2k_udp_path_post(d2k_udp_path *pp, int fed, const d2k_key *key,
                      const d2k_result *res, d2k_udp_hold_batch *batch);

/* A datagram d2kd has just ACCEPTed plainly (no hold, no plan).  When it opened
 * a client UDP flow (the session's first client datagram on the tuple), the
 * datagrams queued right behind it reached conntrack while it was still
 * queued and would clash: mark the flow for d2k_udp_out_late, exactly like a
 * released hold.  Field 03.10.2026 after 4ed54d4: an unparseable-Initial burst
 * lost its 2nd..4th datagrams this way (16 of 24).  Returns 1 when marked.
 * IPv4 only: the measured loss is the NAT clash; IPv6 has no NAT here and the
 * kernel resolves its UDP clashes, so its datagrams keep the kernel path.  A
 * marked (policy-routed) opening datagram is not marked either.  A flow first
 * seen mid-life (d2kd restart, flow-table eviction) still counts as opening:
 * its next datagrams within the window are re-sent needlessly but harmlessly
 * (no conntrack "NEW" information reaches the queue today). */
int d2k_udp_path_passed(d2k_udp_path *pp, const uint8_t *pkt, size_t len,
                        uint32_t mark, uint64_t now_ns);

#endif
