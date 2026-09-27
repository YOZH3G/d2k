/* STUN-only regression: intentionally contains no QUIC vectors or assertions. */
#include <stdio.h>
#include <string.h>
#include "d2k_journal.h"
#include "d2k_session.h"

static int fails;
#define CHECK(ok, msg) do { \
    if (!(ok)) { printf("FAIL: %s\n", msg); fails++; } \
} while (0)

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static size_t binding(uint8_t *p, uint16_t type, const uint8_t txid[12]) {
    memset(p, 0, 20);
    p[0] = (uint8_t)(type >> 8);
    p[1] = (uint8_t)type;
    p[4] = 0x21; p[5] = 0x12; p[6] = 0xa4; p[7] = 0x42;
    memcpy(p + 8, txid, 12);
    return 20;
}

static size_t udp_packet(uint8_t *p, int reverse, uint16_t client_port,
                         const uint8_t *payload, size_t payload_len) {
    size_t n = 28 + payload_len;
    memset(p, 0, n);
    p[0] = 0x45;
    wr16(p + 2, (uint16_t)n);
    p[8] = 64;
    p[9] = 17;
    if (!reverse) {
        memcpy(p + 12, "\xc0\xa8\x01\x43", 4);
        memcpy(p + 16, "\x01\x02\x03\x04", 4);
        wr16(p + 20, client_port);
        wr16(p + 22, 3478);
    } else {
        memcpy(p + 12, "\x01\x02\x03\x04", 4);
        memcpy(p + 16, "\xc0\xa8\x01\x43", 4);
        wr16(p + 20, 3478);
        wr16(p + 22, client_port);
    }
    wr16(p + 24, (uint16_t)(8 + payload_len));
    if (payload_len) { memcpy(p + 28, payload, payload_len); }
    return n;
}

static size_t journal_kind(const d2k_session *s, uint8_t kind, uint8_t code) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t found = 0;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind && e->code == code) { found++; }
    }
    return found;
}

int main(void) {
    const uint8_t txid[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
    uint8_t req[20], resp[20], alien[12], pkt[64], outbuf[512];
    d2k_result result;
    binding(req, 0x0001, txid);
    binding(resp, 0x0101, txid);
    memcpy(alien, txid, sizeof alien);
    alien[0] ^= 0xff;
    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "session allocation");
    if (!s) { return 1; }

    size_t n = udp_packet(pkt, 0, 64041, req, sizeof req);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_session_packet(s, pkt, n, 1000, outbuf, sizeof outbuf, &result);
    CHECK(d2k_session_hellos(s) == 1, "valid Binding Request is recognized");
    CHECK(journal_kind(s, D2K_JRN_HELLO_SNI, 0) == 1,
          "STUN request enters the voice-class observation path");

    binding(req, 0x0101, alien);
    n = udp_packet(pkt, 1, 64041, req, sizeof req);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 1100, outbuf, sizeof outbuf, &result);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 0,
          "foreign transaction ID is not STUN proof");

    n = udp_packet(pkt, 1, 64041, resp, sizeof resp);
    d2k_session_packet(s, pkt, n, 1200, outbuf, sizeof outbuf, &result);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 1,
          "matching transaction ID proves a STUN exchange");
    d2k_session_free(s);

    s = d2k_session_new(8, 16);
    CHECK(s != NULL, "malformed-case session allocation");
    if (s) {
        uint8_t malformed[20] = {0};
        malformed[4] = 0x21; malformed[5] = 0x12;
        malformed[6] = 0xa4; malformed[7] = 0x42;
        n = udp_packet(pkt, 0, 64042, malformed, sizeof malformed);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        d2k_session_packet(s, pkt, n, 2000, outbuf, sizeof outbuf, &result);
        CHECK(d2k_session_hellos(s) == 0, "malformed STUN is not a voice request");
        d2k_session_free(s);
    }

    if (fails) { return 1; }
    puts("STUN datapath proof: all checks passed");
    return 0;
}
