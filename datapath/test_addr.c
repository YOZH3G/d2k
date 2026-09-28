#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "d2k_addr.h"
#include "d2k_packet.h"

int main(void) {
    {
        uint8_t pkt[80] = {0x60};
        pkt[5] = 28; pkt[6] = 0; pkt[7] = 55;
        pkt[8] = 0x20; pkt[23] = 1; pkt[24] = 0x20; pkt[39] = 2;
        pkt[40] = 6; pkt[41] = 0; pkt[60] = 0x50;
        d2k_packet_view v;
        assert(d2k_packet_parse(pkt, 68, &v));
        assert(v.family == 6 && v.protocol == 6 && v.l4 == 48 && v.total == 68);
        assert(v.src.bytes[15] == 1 && v.dst.bytes[15] == 2 && v.hop_limit == 55);
        pkt[42] = 5;
        assert(!d2k_packet_parse(pkt, 68, &v)); /* do not strip meaningful options */
        pkt[42] = 0;
        assert(!d2k_packet_parse(pkt, 67, &v));
        pkt[41] = 255;
        assert(!d2k_packet_parse(pkt, 68, &v));
        pkt[41] = 0; pkt[6] = 44;
        assert(!d2k_packet_parse(pkt, 68, &v)); /* fragments bypass untouched */
        pkt[6] = 43;
        assert(!d2k_packet_parse(pkt, 68, &v)); /* routing header unsupported */
        pkt[6] = 58;
        assert(!d2k_packet_parse(pkt, 68, &v)); /* ICMPv6 never intercepted */
        pkt[6] = 17; pkt[5] = 8;
        assert(d2k_packet_parse(pkt, 48, &v) && v.l4 == 40);
        pkt[5] = 0;
        assert(!d2k_packet_parse(pkt, 48, &v)); /* no jumbograms */
    }
    d2k_addr a, b;
    char text[64];
    assert(d2k_addr_parse("2001:db8::1", &a) == 0);
    assert(a.family == 6 && a.bytes[0] == 0x20 && a.bytes[15] == 1);
    assert(d2k_addr_text(&a, text, sizeof text) == 11);
    assert(strcmp(text, "2001:db8::1") == 0);
    assert(d2k_addr_parse("2001:0db8:0:0:0:0:0:1", &b) == 0);
    assert(d2k_addr_equal(&a, &b));
    assert(d2k_addr_parse("2002:db8::1", &b) == 0);
    assert(!d2k_addr_equal(&a, &b));
    assert(d2k_addr_text(&a, text, 4) == 0);
    assert(d2k_addr_parse("192.0.2.1", &a) == 0);
    assert(a.family == 4 && a.bytes[0] == 192 && a.bytes[3] == 1);
    for (size_t i = 4; i < sizeof a.bytes; ++i) assert(a.bytes[i] == 0);
    assert(d2k_addr_text(&a, text, sizeof text) == 9);
    assert(strcmp(text, "192.0.2.1") == 0);
    assert(d2k_addr_parse("::ffff:192.0.2.1", &b) == 0);
    assert(b.family == 6 && !d2k_addr_equal(&a, &b));
    const char *bad[] = {"", "host.example", "2001:::1", "256.0.0.1",
                         "::1junk", "[::1]", "fe80::1%eth0"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        b = a;
        int rc = d2k_addr_parse(bad[i], &b);
        if (rc != -1) fprintf(stderr, "accepted invalid literal: %s\n", bad[i]);
        assert(rc == -1);
        assert(d2k_addr_equal(&a, &b));
    }
    assert(d2k_addr_parse(NULL, &a) == -1);
    assert(d2k_addr_parse("::1", NULL) == -1);
    assert(d2k_addr_text(NULL, text, sizeof text) == 0);
    assert(d2k_addr_text(&a, NULL, 0) == 0);
    b.family = 7;
    assert(!d2k_addr_equal(&b, &b));
    assert(d2k_addr_text(&b, text, sizeof text) == 0);
    puts("address: all tests passed");
    return 0;
}
