#ifndef D2K_UDPRUNTIME_H
#define D2K_UDPRUNTIME_H
#include "d2k_wire.h"
#include "d2k_quic_arms.h"
#define D2K_UDP_BATCH_MAX D2K_WIRE_BATCH_MAX
#define D2K_UDP_BATCH_BYTES (D2K_UDP_BATCH_MAX * 4096u)
typedef struct {
    uint8_t *bytes;
    size_t used, n;
    struct {size_t off,len; uint32_t delay_us; int fragment;} v[D2K_UDP_BATCH_MAX];
} d2k_udp_batch;
/* Complete construction before the first send. Identical PlanApply and wire
 * builders to the datapath. Context and fragment ID are explicit for replay. */
int d2k_udp_plan_build(const char *text,const d2k_conn *c,uint32_t fragment_id,
    const uint8_t *payload,size_t len,d2k_udp_batch *out);
void d2k_udp_batch_free(d2k_udp_batch *b);
int d2k_quic_question_plan(const d2k_quic_arm_question *q,char *text,size_t cap);
/* Connected socket is a sink, not a bypass engine. IP headers of ordinary
 * datagrams belong to the kernel; payload, hop limit and timing come from Plan. */
int d2k_udp_plan_send(int fd,const char *text,const uint8_t *payload,size_t len,
    uint32_t mark);
#endif
