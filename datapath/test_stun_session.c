/* STUN-only regression: intentionally contains no QUIC vectors or assertions. */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
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

/* Объявленный голосом план (тот же, что plan_voice_declared в
   test_quic_session.c): REC_PROTO транспорт 17, протокол voice. */
static const uint8_t plan_voice[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x02, 0x00, 0x02, 0x11, 0x03,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x00, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Задача 15: экран отдаёт датапату только первые 8 пакетов потока
   (S99d2k, connbytes 0:8), и разговор, шедший во время замера, к моменту
   установки опыта уже невидим. Опыт — клиент LAN + точка STUN-сервера +
   любой клиентский порт + trial ID: его получает первый Binding Request
   следующего потока того же клиента; другой клиент и истёкший lease — нет. */
static void live_trial(void) {
    const uint8_t txid[12] = {9,9,9,9,9,9,9,9,9,9,9,9};
    const uint8_t trial[D2K_TRIAL_ID_LEN] = {0x51,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint64_t ms = 1000000ull;
    uint8_t req[20], resp[20], junk[40], pkt[96], outbuf[1024];
    d2k_result result;
    binding(req, 0x0001, txid);
    binding(resp, 0x0101, txid);
    memset(junk, 0x80, sizeof junk);
    d2k_session *s = d2k_session_new(8, 32);
    CHECK(s != NULL, "live-trial session allocation");
    if (!s) { return; }
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    /* The call during measurement: only its first 8 packets are queued. */
    size_t n = udp_packet(pkt, 0, 64050, req, sizeof req);
    d2k_session_packet(s, pkt, n, 1 * ms, outbuf, sizeof outbuf, &result);
    for (int i = 0; i < 7; i++) {
        n = udp_packet(pkt, 0, 64050, junk, sizeof junk);
        d2k_session_packet(s, pkt, n, 2 * ms, outbuf, sizeof outbuf, &result);
    }
    d2k_addr_probe_flow f;
    memset(&f, 0, sizeof f);
    f.family = 4;
    memcpy(f.src_ip4, "\xc0\xa8\x01\x43", 4);
    memcpy(f.dst_ip4, "\x01\x02\x03\x04", 4);
    f.src_port_be = 0;
    f.dst_port_be = htons(3478);
    f.transport = 17;
    const uint64_t expires = 10 * ms + 120000 * ms;
    d2k_plan *p = NULL;
    char err[160];
    CHECK(d2k_plan_load(plan_voice, sizeof plan_voice, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_addr_probe(d2k_session_plans(s), &f, trial, 10 * ms,
                                     expires, p) == 0,
          "voice trial installs on client + STUN endpoint, any client port");
    n = udp_packet(pkt, 0, 64051, req, sizeof req);
    pkt[15] = 0x44;   /* another LAN client */
    d2k_session_packet(s, pkt, n, 20 * ms, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "another LAN client does not get the voice trial");
    n = udp_packet(pkt, 0, 64052, req, sizeof req);
    d2k_session_packet(s, pkt, n, 30 * ms, outbuf, sizeof outbuf, &result);
    CHECK(result.applied && memcmp(result.trial_id, trial, sizeof trial) == 0,
          "next STUN flow of the same client gets the trial with its trial ID");
    n = udp_packet(pkt, 1, 64052, resp, sizeof resp);
    d2k_session_set_hook(s, D2K_HOOK_FORWARD);
    d2k_session_packet(s, pkt, n, 40 * ms, outbuf, sizeof outbuf, &result);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    CHECK(journal_kind(s, D2K_JRN_EXCHANGE, D2K_UDP_PROOF_STUN) == 1,
          "STUN response for our txid on the trial flow is protocol proof");
    n = udp_packet(pkt, 0, 64053, req, sizeof req);
    d2k_session_packet(s, pkt, n, expires + 1, outbuf, sizeof outbuf, &result);
    CHECK(!result.applied, "expired voice trial matches nothing");
    d2k_session_free(s);
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

    live_trial();

    if (fails) { return 1; }
    puts("STUN datapath proof: all checks passed");
    return 0;
}
