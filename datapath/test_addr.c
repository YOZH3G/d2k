#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "d2k_addr.h"

int main(void) {
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
