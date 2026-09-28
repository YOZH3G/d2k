#include "tg_wire.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static void test_mux(void) {
    uint8_t raw[8];
    const uint8_t payload[] = {0xaa, 0xbb};
    tg_frame f;
    assert(tg_mux_encode(raw, sizeof(raw), 0x0102, 2, payload,
                         sizeof(payload)) == sizeof(payload) + 3);
    assert(raw[0] == 1 && raw[1] == 2 && raw[2] == 2);
    assert(tg_mux_decode(raw, sizeof(payload) + 3, &f) == 0);
    assert(f.stream_id == 0x0102 && f.type == 2);
    assert(f.payload_len == 2 && memcmp(f.payload, payload, 2) == 0);
    assert(tg_mux_encode(raw, 4, 1, 2, payload, sizeof(payload)) == 0);
    assert(tg_mux_decode(raw, 2, &f) != 0);
}

static void test_connect(void) {
    uint8_t out[19];
    size_t n = 0;
    const uint8_t v4[4] = {149, 154, 167, 51};
    const uint8_t v4_expected[7] = {1,149,154,167,51,1,187};
    assert(tg_connect_encode(out, sizeof(out), AF_INET, v4, 443, &n) == 0);
    assert(n == sizeof(v4_expected) && memcmp(out, v4_expected, n) == 0);
    const uint8_t v6[16] = {0x20,1,0x0b,0x28,0xf2,0x3d,0,1,
                            0,0,0,0,0,0,0,0x0a};
    assert(tg_connect_encode(out, sizeof(out), AF_INET6, v6, 443, &n) == 0);
    assert(n == 19 && out[0] == 4 && out[17] == 1 && out[18] == 187);
    assert(tg_connect_encode(out, sizeof(out), AF_INET, v4, 0, &n) != 0);
    assert(tg_connect_encode(out, 6, AF_INET, v4, 443, &n) != 0);
}

static void test_hello_and_ack(void) {
    uint8_t hello[16], ack[64];
    size_t n = 0;
    tg_hello_ack decoded;
    const uint8_t want_hello[] = {2,2,'b','7',0,0,0,0};
    assert(tg_hello_encode(hello, sizeof(hello), "b7", 0, &n) == 0);
    assert(n == sizeof(want_hello) && memcmp(hello, want_hello, n) == 0);
    const uint8_t expected_ack[] = {
        2,1,2,3,4,5,6,7,8,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        2,'b','1', 0x10,0x20,0x30,0x40, 0x50,0x60,0x70,0x80
    };
    memcpy(ack, expected_ack, sizeof(expected_ack));
    assert(tg_hello_ack_decode(ack, sizeof(expected_ack), &decoded) == 0);
    assert(decoded.version == 2 && decoded.server_unix == INT64_C(0x0102030405060708));
    assert(memcmp(decoded.nonce, expected_ack + 9, 16) == 0);
    assert(decoded.min_build_len == 2 && memcmp(decoded.min_build, "b1", 2) == 0);
    assert(decoded.window == UINT32_C(0x10203040));
    assert(decoded.capabilities == UINT32_C(0x50607080));
    assert(tg_hello_ack_decode(ack, sizeof(expected_ack)-1, &decoded) != 0);
}

static void test_auth_v2_layout(void) {
    uint8_t payload[TG_AUTH_V2_LEN], id[16], nonce[16], sig[64];
    for (size_t i = 0; i < sizeof(id); ++i) id[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0x20 + i);
    memset(sig, 0x5a, sizeof(sig));
    assert(tg_auth_v2_encode(payload, id, UINT64_C(0x0102030405060708),
                             nonce, sig) == 0);
    assert(memcmp(payload, id, 16) == 0);
    assert(memcmp(payload + 16, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0);
    assert(memcmp(payload + 24, nonce, 16) == 0);
    assert(memcmp(payload + 40, sig, 64) == 0);
}

static void test_info_and_close(void) {
    const uint8_t info[] = {3, 0x01,0x02,0x03,0x04, 'o','k'};
    const uint8_t close[] = {8, 'n','o'};
    uint8_t kind, reason;
    uint32_t arg;
    const uint8_t *text;
    size_t text_len;
    assert(tg_info_decode(info, sizeof(info), &kind, &arg, &text, &text_len) == 0);
    assert(kind == 3 && arg == UINT32_C(0x01020304));
    assert(text_len == 2 && memcmp(text, "ok", 2) == 0);
    assert(tg_info_decode(info, 4, &kind, &arg, &text, &text_len) != 0);
    assert(tg_close_decode(close, sizeof(close), &reason, &text, &text_len) == 0);
    assert(reason == 8 && text_len == 2 && memcmp(text, "no", 2) == 0);
    assert(tg_close_decode(NULL, 0, &reason, &text, &text_len) == 0);
    assert(reason == 0 && text_len == 0);
}

static void test_window(void) {
    uint8_t encoded[4];
    uint32_t credit = 0;
    const uint8_t expected[4] = {0x12,0x34,0x56,0x78};
    assert(tg_window_encode(encoded, UINT32_C(0x12345678)) == 0);
    assert(memcmp(encoded, expected, sizeof(expected)) == 0);
    assert(tg_window_decode(encoded, sizeof(encoded), &credit) == 0);
    assert(credit == UINT32_C(0x12345678));
    assert(tg_window_decode(encoded, 3, &credit) != 0);
}

int main(void) {
    test_mux();
    test_connect();
    test_hello_and_ack();
    test_auth_v2_layout();
    test_info_and_close();
    test_window();
    puts("wire tests: ok");
    return 0;
}
