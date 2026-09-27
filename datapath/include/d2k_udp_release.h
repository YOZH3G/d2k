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

/* Absolute deadline of the earliest pending batch; zero when empty. */
uint64_t d2k_udp_release_next_ns(const d2k_udp_release *q);

#endif
