#ifndef D2K_PACKET_H
#define D2K_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "d2k_addr.h"

/* Read-only bounded IP view shared by capture, holding and execution.
 * Unsupported packets return 0: callers must pass them unchanged, not drop.
 * Routing, AH/ESP, IPv6 fragments and jumbograms need separate semantics. */
typedef struct {
    d2k_addr src, dst;
    size_t total, l4;
    uint8_t family, protocol, hop_limit, traffic_class;
    uint32_t flow_label;
    uint16_t fragment, ip_id;
} d2k_packet_view;

static inline unsigned d2k_packet_u16(const uint8_t *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

static inline int d2k_packet_parse(const uint8_t *p, size_t n, d2k_packet_view *out) {
    if (!p || !out || n < 20) { return 0; }
    d2k_packet_view v;
    memset(&v, 0, sizeof v);
    v.family = p[0] >> 4;
    v.src.family = v.dst.family = v.family;
    if (v.family == 4) {
        v.l4 = (p[0] & 15u) * 4u;
        v.total = d2k_packet_u16(p + 2);
        if (v.l4 < 20 || v.total < v.l4 || v.total > n) { return 0; }
        v.fragment = (uint16_t)d2k_packet_u16(p + 6);
        if (v.fragment & 0x1fffu) { return 0; }
        v.ip_id = (uint16_t)d2k_packet_u16(p + 4);
        v.protocol = p[9]; v.hop_limit = p[8]; v.traffic_class = p[1];
        memcpy(v.src.bytes, p + 12, 4); memcpy(v.dst.bytes, p + 16, 4);
    } else if (v.family == 6) {
        if (n < 40) { return 0; }
        size_t payload = d2k_packet_u16(p + 4);
        if (!payload || payload > n - 40) { return 0; }
        v.total = 40 + payload; v.l4 = 40;
        v.protocol = p[6]; v.hop_limit = p[7];
        v.traffic_class = (uint8_t)(((p[0] & 15u) << 4) | (p[1] >> 4));
        v.flow_label = ((uint32_t)(p[1] & 15u) << 16) | ((uint32_t)p[2] << 8) | p[3];
        memcpy(v.src.bytes, p + 8, 16); memcpy(v.dst.bytes, p + 24, 16);
        unsigned headers = 0;
        while (v.protocol == 0 || v.protocol == 60) {
            if (++headers > 8 || v.total - v.l4 < 8) { return 0; }
            size_t ext = ((size_t)p[v.l4 + 1] + 1) * 8;
            if (ext > v.total - v.l4) { return 0; }
            /* Builders may omit padding-only extensions. Never silently
             * strip Router Alert or any other option with actual semantics. */
            for (size_t o = 2; o < ext;) {
                uint8_t option = p[v.l4 + o];
                if (option == 0) { o++; continue; } /* Pad1 */
                if (option != 1 || ext - o < 2) { return 0; }
                size_t pad = (size_t)p[v.l4 + o + 1] + 2;
                if (pad > ext - o) { return 0; }
                o += pad;
            }
            v.protocol = p[v.l4]; v.l4 += ext;
        }
    } else { return 0; }
    size_t min = v.protocol == 6 ? 20 : v.protocol == 17 ? 8 : 0;
    if (!min || v.total - v.l4 < min) { return 0; }
    *out = v;
    return 1;
}

#endif
