#include <arpa/inet.h>
#include <string.h>
#include "d2k_addr.h"

int d2k_addr_parse(const char *text, d2k_addr *out) {
    if (!text || !out || strchr(text, '%')) return -1;
    d2k_addr value;
    memset(&value, 0, sizeof value);
    if (inet_pton(AF_INET, text, value.bytes) == 1) {
        value.family = 4;
    } else if (inet_pton(AF_INET6, text, value.bytes) == 1) {
        value.family = 6;
    } else {
        return -1;
    }
    *out = value;
    return 0;
}

size_t d2k_addr_text(const d2k_addr *addr, char *out, size_t cap) {
    if (!addr || !out || !cap) return 0;
    int af = addr->family == 4 ? AF_INET : addr->family == 6 ? AF_INET6 : 0;
    if (!af) return 0;
    char text[INET6_ADDRSTRLEN];
    if (!inet_ntop(af, addr->bytes, text, sizeof text)) return 0;
    size_t n = strlen(text);
    if (n >= cap) return 0;
    memcpy(out, text, n + 1);
    return n;
}

int d2k_addr_equal(const d2k_addr *a, const d2k_addr *b) {
    if (!a || !b || a->family != b->family) return 0;
    size_t n = a->family == 4 ? 4 : a->family == 6 ? 16 : 0;
    return n && memcmp(a->bytes, b->bytes, n) == 0;
}
