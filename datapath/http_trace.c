#include "d2k_http_trace.h"
#include "d2k_http80.h"
#include "d2k_packet.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

size_t d2k_http_trace(char *line, size_t cap, const uint8_t *packet, size_t len,
                      const d2k_result *result, const d2k_http_trace_outcome *outcome) {
    if (!line || !cap) { return 0; }
    line[0] = 0;
    d2k_packet_view ip;
    if (!result || !outcome || !d2k_packet_parse(packet, len, &ip) || ip.protocol != 6) { return 0; }
    const uint8_t *tcp = packet + ip.l4;
    size_t th = (tcp[12] >> 4) * 4u;
    if (d2k_packet_u16(tcp + 2) != 80 || th < 20 || th >= ip.total - ip.l4) { return 0; }
    const uint8_t *request = tcp + th;
    size_t request_len = ip.total - ip.l4 - th;
    size_t method = 0;
    while (method < request_len && request[method] >= 'A' && request[method] <= 'Z') { method++; }
    if (!method || method == request_len || request[method] != ' ') { return 0; }
    char host[256] = "<unparsed>", src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    d2k_http_req hr;
    if (d2k_http_request(request, request_len, &hr) && hr.host_len < sizeof host) {
        memcpy(host, request + hr.host_off, hr.host_len); host[hr.host_len] = 0;
    }
    int af = ip.family == 6 ? AF_INET6 : AF_INET;
    if (!inet_ntop(af, ip.src.bytes, src, sizeof src) || !inet_ntop(af, ip.dst.bytes, dst, sizeof dst)) { return 0; }
    char plan[D2K_PLAN_ID_LEN * 2 + 1] = "-";
    if (result->applied) {
        for (size_t i = 0; i < D2K_PLAN_ID_LEN; i++) { snprintf(plan + i * 2, 3, "%02x", result->plan_id[i]); }
    }
    const char *status = !outcome->apply ? "OBSERVE" :
        !result->applied ? "SKIPPED" :
        outcome->output_failed || outcome->original_failed ? "FAILED" :
        outcome->pending || outcome->original_pending ? "PENDING" : "COMPLETE";
    uint32_t seq = (uint32_t)tcp[4] << 24 | (uint32_t)tcp[5] << 16 | (uint32_t)tcp[6] << 8 | tcp[7];
    int n = snprintf(line, cap,
        "d2kd: HTTP execution host=%s IPv%u [%s]:%u -> [%s]:80 seq=%" PRIu32
        " hook=%u mark=0x%x outdev=%u status=%s prepared=%u plan=%s execution=%" PRIu64
        " planned=%zu raw_sent=%zu queued=%zu original=%s output_failed=%d reason=%s",
        host, ip.family, src, d2k_packet_u16(tcp), dst, seq,
        outcome->hook, outcome->mark, outcome->outdev, status, (unsigned)result->applied,
        plan, result->execution_id, outcome->planned, outcome->sent, outcome->queued,
        outcome->original_failed ? "FAILED" : outcome->original_pending ? "PENDING" :
        outcome->verdict ? "ACCEPT" : "DROP",
        outcome->output_failed, result->skipped ? result->skipped : "-");
    return n < 0 ? 0 : (size_t)n < cap ? (size_t)n : cap - 1;
}
