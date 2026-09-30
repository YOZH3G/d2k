#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_link.h"
#include "d2k_plantlv.h"
#include "d2k_verify.h"
#include "d2k_meas.h"

int main(int argc, char **argv) {
    if (argc != 4 && argc != 5) return 2;
    const char *ip = argv[1], *name = argv[2];
    uint8_t address[16];
    uint8_t family = inet_pton(AF_INET6, ip, address) == 1 ? 6 : 4;
    if (family == 4 && inet_pton(AF_INET, ip, address) != 1) return 2;
    size_t hello = (size_t)strtoul(argv[3], NULL, 10);
    char text[8192], hex[16384], err[200];
    if (d2k_rx_volume_plan(0, D2K_SHAPE_MODERN, 1492, text, sizeof text)) return 3;
    /* Explicit comparison fixture from the failing field catalog, not a
       runtime strategy import. Still isolated to this probe's source port. */
    if (argc == 5) {
        if (strcmp(argv[4], "saved") != 0 && strcmp(argv[4], "saved-gzip") != 0) return 2;
        snprintf(text, sizeof text,
            "d2k-plan 1 6\nid 00000000000000000000000000000000\n"
            "proto tcp tls\nwire detect-tcp-v1\ninput tls-sni\nsegment 1400\n"
            "payload-pad64 2 1 15\nseqovl payload=2 poison=0\n"
            "split payload_start +1\norder forward\n");
    }
    char *id = strstr(text, "id ");
    if (!id) return 3;
    memcpy(id + 3, "f5a881fa635648db9c918b81f04b9961", 32);
    if (d2k_plan_text_to_hex(text, hex, sizeof hex, err, sizeof err)) return 4;
    int link = d2k_link_open("/opt/d2k/run/d2kd.sock", err, sizeof err);
    if (link < 0) { puts(err); return 5; }
    int fd = -1; uint16_t port = 0;
    if (d2k_props_bind_family(family, &fd, &port) || !port || d2k_mark_hook(fd, 0x2e)) return 6;
    if (d2k_link_set_name_family(link, name, 6, hex, D2K_SHAPE_MODERN, port, family, err, sizeof err)) {
        puts(err); close(fd); d2k_link_close(link); return 7;
    }
    printf("probe port=%u hello=%zu\n", (unsigned)ntohs(port), hello);
    fflush(stdout);
    d2k_ver_result r = argc == 5 && strcmp(argv[4], "saved-gzip") == 0
        ? d2k_verify_probe_on(fd, ip, 443, name, 8000, hello)
        : d2k_verify_probe_identity_on(fd, ip, 443, name, 8000, hello, 0);
    printf("level=%d HTTP=%d bytes=%llu/%llu complete=%d reason=%s\n",
        r.level, r.status, (unsigned long long)r.body_bytes,
        (unsigned long long)r.body_expected, r.body_complete, r.reason);
    printf("framing_valid=%d content_length=%d chunked=%d encoding=%d\n",
           r.body_framing_valid, r.body_has_length, r.body_chunked, r.body_encoding);
    int applied = 0;
    for (int i = 0; i < 100; i++) {
        d2k_ev ev;
        if (d2k_link_next(link, &ev, 20, err, sizeof err)) break;
        if (ev.kind == D2K_EV_APPLIED && !memcmp(ev.plan_id,
            (uint8_t[]){0xf5,0xa8,0x81,0xfa,0x63,0x56,0x48,0xdb,0x9c,0x91,0x8b,0x81,0xf0,0x4b,0x99,0x61},16)) applied++;
    }
    printf("applied=%d\n", applied);
    d2k_verify_close(&r);
    int removed = d2k_link_del_name_probe_family(link, name, 6, D2K_SHAPE_MODERN, port, family, err, sizeof err);
    if (removed) puts(err);
    d2k_link_close(link);
    return !(r.status == 200 && r.body_complete && applied && !removed);
}
