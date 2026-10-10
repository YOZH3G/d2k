/* Shared runtime-equality gate. Feed captured packets from both real entry
 * points in the same explicit context. Never normalize bytes before comparing:
 * IDs, checksums, ordering and pacing are part of the measured program.
 * This is a local execution assertion, not a physical packet capture. */
#ifndef D2K_TEST_RUNTIME_TRACE_H
#define D2K_TEST_RUNTIME_TRACE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef struct {
    const uint8_t *bytes;
    size_t len;
    uint32_t delay_us;
} d2k_test_packet;
static inline int d2k_test_packet_equal(const d2k_test_packet *a,const d2k_test_packet *b) {
    return a && b && a->bytes && b->bytes && a->len && a->len==b->len &&
           a->delay_us==b->delay_us && !memcmp(a->bytes,b->bytes,a->len);
}
static inline int d2k_test_trace_equal(const d2k_test_packet *a,size_t an,
                                      const d2k_test_packet *b,size_t bn) {
    if(!a || !b || !an || an!=bn)return 0;
    for(size_t i=0;i<an;i++)if(!d2k_test_packet_equal(a+i,b+i))return 0;
    return 1;
}
#endif
