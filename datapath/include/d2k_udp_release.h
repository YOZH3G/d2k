/* d2k_udp_release.h — bounded delayed verdict ownership for held UDP input. */
#ifndef D2K_UDP_RELEASE_H
#define D2K_UDP_RELEASE_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_track.h"
#include "d2k_udp_hold.h"

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

/* Who releases each held original of a held UDP batch (tasks 42, 46).
 *
 * Every datagram after the first one reached conntrack while the head was
 * still queued, so it carries its own unconfirmed entry.  Released to the
 * kernel after the head (or after our raw fakes) it loses the insert and is
 * dropped (insert_failed/drop; router 02.10 and 03.10.2026: 61 of 61
 * increments).  So the tails never go back to the kernel when a raw path
 * exists: they are re-sent byte for byte right after the head, through the
 * entry the head (or the plan) has just confirmed, and their queued copies
 * are dropped.
 *
 * owned != 0: the plan took the head as its own last emit (fate drop): the
 * head's copy is dropped as well.
 * owned == 0: the head gets head_verdict (it is the one datagram whose entry
 * may still win), the tails are re-sent when can_resend.
 * can_resend == 0 (observe mode, no raw socket): old split, tails ACCEPT.
 * Returns how many originals the caller must re-send itself. */
size_t d2k_udp_replay_fates(size_t count, uint32_t head_verdict, int owned,
                            int can_resend, uint32_t *verdicts, uint8_t *resend);

/* Re-sends one original datagram verbatim through the raw path (or queues it
 * behind the plan's deferred emits).  Zero when it left or was queued. */
typedef int (*d2k_udp_resend)(void *ctx, const uint8_t *pkt, size_t len);

/* Releases a held batch in the only order that keeps every datagram: the
 * head's verdict first (nf_reinject confirms its entry inside that call), then
 * for each tail in arrival order its re-send and then the DROP of its queued
 * copy.  A tail whose re-send fails is ACCEPTed instead (fail open, logged by
 * the caller).  Every ID gets exactly one verdict; the head is never re-sent.
 * *verdict_failed is set when any verdict could not be sent; *resend_failed
 * counts tails that fell back to ACCEPT.  Returns the number of tails re-sent. */
size_t d2k_udp_release_batch(const d2k_udp_hold_batch *b, uint32_t head_verdict,
                             int owned, int can_resend,
                             d2k_udp_release_send verdict, d2k_udp_resend resend,
                             void *ctx, int *verdict_failed, size_t *resend_failed);

/* Datagrams of a released flow that were already queued but not in its batch
 * (the head was ready alone; 0-RTT, a split-ClientHello tail or a PTO repeat
 * arriving right behind it) carry the same unconfirmed-entry clash.  The
 * caller marks each released head; a later queued client datagram of the same
 * 5-tuple and direction inside D2K_UDP_FOLLOW_NS is re-sent the same way.
 * Re-sending one whose entry is already confirmed is harmless: the raw copy
 * finds that entry and keeps its NAT mapping (router 03.10.2026, tail on the
 * same external port).  The window only bounds the cost. */
#define D2K_UDP_FOLLOW_SLOTS 64
#define D2K_UDP_FOLLOW_NS UINT64_C(100000000)

typedef struct d2k_udp_follow d2k_udp_follow;
d2k_udp_follow *d2k_udp_follow_new(void);
void d2k_udp_follow_free(d2k_udp_follow *f);
/* Remembers the head's client tuple until now_ns + D2K_UDP_FOLLOW_NS.  A full
 * table drops the entry closest to expiry.  Non-zero for a non-UDP packet. */
int d2k_udp_follow_mark(d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                        uint64_t now_ns);
/* One when pkt is a whole (unfragmented) UDP datagram of a marked tuple in the
 * client's direction and the window is still open. */
int d2k_udp_follow_match(const d2k_udp_follow *f, const uint8_t *pkt, size_t len,
                         uint64_t now_ns);

/* Absolute deadline of the earliest pending batch; zero when empty. */
uint64_t d2k_udp_release_next_ns(const d2k_udp_release *q);

#endif
