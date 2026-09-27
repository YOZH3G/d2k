/* d2k_udp_hold.h — bounded ownership for QUIC/UDP datagrams.
 *
 * UDP is datagram-oriented: a split QUIC ClientHello must be held as the
 * original IPv4 datagrams and replayed in FIFO order.  This module never
 * concatenates payloads and never decides whether a plan is applicable.
 */
#ifndef D2K_UDP_HOLD_H
#define D2K_UDP_HOLD_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_hold.h"

#define D2K_UDP_HOLD_SLOTS 16
#define D2K_UDP_HOLD_PACKETS 8
#define D2K_UDP_HOLD_PACKET 1600
#define D2K_UDP_HOLD_WAIT_NS UINT64_C(100000000)

typedef struct d2k_udp_hold d2k_udp_hold;

typedef struct {
    d2k_key key;
    size_t count;
    uint32_t ids[D2K_UDP_HOLD_PACKETS];
    size_t len[D2K_UDP_HOLD_PACKETS];
    uint8_t packets[D2K_UDP_HOLD_PACKETS][D2K_UDP_HOLD_PACKET];
} d2k_udp_hold_batch;

d2k_udp_hold *d2k_udp_hold_new(void);
void d2k_udp_hold_free(d2k_udp_hold *h,
                       d2k_hold_release release, void *ctx);

/* Stores the complete original datagram.  Returns 1 when the ID is owned by
 * the hold table, 0 when the caller retains ownership.  A malformed/oversize
 * datagram is never partially stored. */
int d2k_udp_hold_feed(d2k_udp_hold *h, const d2k_key *key, uint32_t id,
                      const uint8_t *packet, size_t len, uint64_t now_ns,
                      d2k_hold_release release, void *ctx);

/* Removes one flow from the table without releasing its IDs.  The caller owns
 * the returned batch and must issue the final verdict for every ID.  Call
 * d2k_udp_hold_flush with the release callback before take when deadlines are
 * being serviced. */
int d2k_udp_hold_take(d2k_udp_hold *h, const d2k_key *key, uint64_t now_ns,
                      d2k_udp_hold_batch *out);

/* Releases expired slots and reports how many original IDs were released. */
size_t d2k_udp_hold_flush(d2k_udp_hold *h, uint64_t now_ns,
                          d2k_hold_release release, void *ctx);

#endif
