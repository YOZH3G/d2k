#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d2k_crypto.h"
#include "d2k_tls13core.h"
#include "d2k_verify.h"
#include "d2k_hello.h"

static int fails;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "ECH check failed at %d: %s\n", __LINE__, #x); fails++; } } while (0)

static int unhex(const char *s, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v = 0;
        for (size_t j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)s[2 * i + j];
            unsigned d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return -1;
            v = v * 16 + d;
        }
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 0;
}

static int contains(const uint8_t *b, size_t n, const char *s) {
    size_t l = strlen(s);
    for (size_t i = 0; i + l <= n; i++) if (!memcmp(b + i, s, l)) return 1;
    return 0;
}

int main(int argc, char **argv) {
    const char *hex = "0045fe0d004137002000200d1bbf3935b6317f6bc0a07894ba03bb3c32dc86758dcf67fef797a98360c97b0004000100010012636c6f7564666c6172652d6563682e636f6d0000";
    uint8_t list[1024]; size_t len = 0;
    CHECK(!unhex(argc == 3 ? argv[2] : hex, list, sizeof list, &len));
    d2k_ech_config config;
    CHECK(!d2k_ech_config_parse(list, len, &config));
    if (fails) return 1;
    if (argc == 3) {
        char *end = NULL;
        long port = strtol(argv[1], &end, 10);
        CHECK(end && !*end && port > 0 && port <= 65535);
        if (fails) return 1;
        d2k_ver_result r = d2k_verify_probe_ech_on(-1, "127.0.0.1", (uint16_t)port,
            "echo.test", &config, 3000, 1541, 0, NULL);
        fprintf(stderr, "ECH interop: accepted=%d name=%d status=%d body=%llu complete=%d: %s\n",
            r.ech_accepted, r.name_ok, r.status, (unsigned long long)r.body_bytes,
            r.body_complete, r.reason);
        CHECK(r.ech_accepted && r.name_ok == 1 && r.level == D2K_VER_APPLICATION &&
              r.status == 200 && r.body_complete && r.body_bytes == 32768);
        d2k_verify_close(&r);
        return fails ? 1 : 0;
    }
    CHECK(!strcmp(config.public_name, "cloudflare-ech.com"));
    for (size_t n = 0; n < len; n++) {
        d2k_ech_config sentinel;
        memset(&sentinel, 0xa5, sizeof sentinel);
        CHECK(d2k_ech_config_parse(list, n, &sentinel) == -1);
        CHECK(sentinel.config_id == 0xa5);
    }
    uint8_t priv[32], hpke[32], rnd[32], outer_rnd[32], pub[32];
    memset(priv, 1, 32); memset(hpke, 2, 32); memset(rnd, 3, 32); memset(outer_rnd, 4, 32);
    CHECK(!d2k_x25519_base(pub, priv));
    d2k_t13_ch_opts o;
    memset(&o, 0, sizeof o);
    o.sni = "echo.test"; o.pub = pub; o.random = rnd;
    o.alpn = "http/1.1"; o.session_id_len = 32; o.pad_to = 1536;
    uint8_t outer[4096], inner[2048]; size_t inner_len = 0;
    size_t n = d2k_t13_ech_build(&o, &config, hpke, outer_rnd,
                                outer, sizeof outer, inner, sizeof inner, &inner_len);
    CHECK(n == 1536 && inner_len > 100);
    CHECK(contains(outer, n, config.public_name));
    CHECK(!contains(outer, n, o.sni));
    CHECK(contains(inner, inner_len, o.sni));
    CHECK(!memcmp(inner + 39, outer + 39, 32));
    uint8_t record[4101], config_id = 0;
    record[0] = 22; record[1] = 3; record[2] = 1;
    record[3] = (uint8_t)(n >> 8); record[4] = (uint8_t)n;
    memcpy(record + 5, outer, n);
    CHECK(d2k_hello_ech_offer(record, n + 5, &config_id) == 1);
    CHECK(config_id == config.config_id);
    CHECK(d2k_hello_ech_offer(record, n + 4, &config_id) == -1);
    CHECK(!d2k_t13_ech_accepted(inner, inner_len, outer, n));
    CHECK(!d2k_t13_ech_build(&o, &config, hpke, outer_rnd,
                            outer, 512, inner, sizeof inner, &inner_len));
    uint8_t bad[1024]; memcpy(bad, list, len);
    bad[7] = 0; bad[8] = 0x21; /* unsupported KEM, not ordinary TLS fallback */
    CHECK(d2k_ech_config_parse(bad, len, &config) == -1);
    fprintf(stderr, "ECH unit: %s\n", fails ? "FAILED" : "passed");
    return fails ? 1 : 0;
}
