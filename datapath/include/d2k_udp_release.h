/* d2k_udp_release.h — bounded delayed verdict ownership for held UDP input. */
#ifndef D2K_UDP_RELEASE_H
#define D2K_UDP_RELEASE_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_track.h"

typedef struct d2k_udp_release d2k_udp_release;

typedef int (*d2k_udp_release_send)(void *ctx, uint32_t id, uint32_t verdict);
typedef void (*d2k_udp_release_done)(void *ctx, const d2k_key *key,
                                    uint64_t token, int complete, size_t sent);

d2k_udp_release *d2k_udp_release_new(size_t slots, size_t batch_size);
void d2k_udp_release_free(d2k_udp_release *q);

/* Takes ownership of a bounded batch until due_ns.  The caller retains the
 * NFQUEUE IDs when this returns non-zero. */
int d2k_udp_release_enqueue(d2k_udp_release *q, uint64_t due_ns,
                            const uint32_t *ids, const uint32_t *verdicts,
                            size_t count, const d2k_key *key, uint64_t token);

/* Releases every due batch in due/arrival order.  A failed send marks that
 * batch incomplete but never leaves its IDs owned forever. */
size_t d2k_udp_release_flush(d2k_udp_release *q, uint64_t now_ns,
                             d2k_udp_release_send send, d2k_udp_release_done done,
                             void *ctx);

/* Who releases each held original of a replayed split-QUIC batch (task 42).
 *
 * owned != 0: the plan took the first original as its own last emit (fate
 * drop) and was handed off without failure.  Every queued copy is dropped,
 * and the tails are re-sent by the caller, in order, right after the plan's
 * emits.  Accepting a queued tail would lose it: it reached conntrack while
 * the head was still queued, so it carries its own unconfirmed entry, and
 * the entry our raw fakes and original already confirmed wins the insert
 * (insert_failed/drop, measured on the router 02.10.2026).
 * owned == 0: the head gets head_verdict and the tails D2K_NF_ACCEPT.
 * Returns how many originals the caller must re-send itself. */
size_t d2k_udp_replay_fates(size_t count, uint32_t head_verdict, int owned,
                            uint32_t *verdicts, uint8_t *resend);

/* Absolute deadline of the earliest pending batch; zero when empty. */
uint64_t d2k_udp_release_next_ns(const d2k_udp_release *q);

#endif
