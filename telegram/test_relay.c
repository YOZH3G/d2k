#include "tg_ws.h"
#include "tg_identity.h"
#include "tg_net.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

static void test_identity_persistence_and_signature(void) {
    char dir[] = "/tmp/d2k-tg-id-XXXXXX";
    char path[256];
    tg_identity first, second;
    uint8_t sig[64], pub[32];
    struct stat st;
    const uint8_t message[] = "relay-auth-vector";
    assert(mkdtemp(dir) != NULL);
    snprintf(path, sizeof(path), "%s/identity", dir);
    assert(tg_identity_load_or_mint(path, &first) == 0);
    assert(strlen(first.install_id_hex) == 32);
    for (size_t i = 0; i < 32; ++i)
        assert((first.install_id_hex[i] >= '0' && first.install_id_hex[i] <= '9') ||
               (first.install_id_hex[i] >= 'a' && first.install_id_hex[i] <= 'f'));
    assert(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    assert(tg_identity_public_key(&first, pub) == 0);
    assert(tg_identity_sign(&first, message, sizeof(message)-1, sig) == 0);
    assert(tg_identity_verify(pub, message, sizeof(message)-1, sig) == 0);
    assert(tg_identity_load_or_mint(path, &second) == 0);
    assert(strcmp(first.install_id_hex, second.install_id_hex) == 0);
    tg_identity_cleanup(&first);
    tg_identity_cleanup(&second);
    unlink(path);
    rmdir(dir);
}

static void test_register_hmac_contract(void) {
    const char body[] = "{\"install_id\":\"0123456789abcdef0123456789abcdef\",\"pubkey\":\"AA==\"}";
    char hex[65];
    assert(tg_register_hmac_hex("secret", body, sizeof(body)-1, hex) == 0);
    assert(strcmp(hex, "ae9ef3a80cf858b2ff72b70ee5ed551624dabfe456b244fcc256e9dbc18a6e52") == 0);
    assert(strcmp(hex, "ae9ef3a80cf858b2ff72b70ee5ed551624dabfe456b244fcc256e9dbc18a6e52") == 0);
    assert(strlen(hex) == 64);
    for (size_t i = 0; i < 64; ++i)
        assert((hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f'));
}

static void test_nip_io_direct_ipv4(void) {
    char ip[16];
    assert(tg_nip_host_to_ipv4("213.176.74.63.nip.io",ip)==1);
    assert(strcmp(ip,"213.176.74.63")==0);
    assert(tg_nip_host_to_ipv4("1.2.3.4.nip.io.",ip)==1);
    assert(strcmp(ip,"1.2.3.4")==0);
    assert(tg_nip_host_to_ipv4("relay.example",ip)==0);
    assert(tg_nip_host_to_ipv4("1.2.3.999.nip.io",ip)==0);
    assert(tg_nip_host_to_ipv4("1.2.3.nip.io",ip)==0);
    assert(tg_nip_host_to_ipv4("+1.2.3.4.nip.io",ip)==0);
    assert(tg_nip_host_to_ipv4(" 1.2.3.4.nip.io",ip)==0);
}

static void test_masked_client_frame(void) {
    const uint8_t msg[] = {0x00,0x7f,0x80,0xff};
    uint8_t frame[32];
    size_t n = 0;
    assert(tg_ws_encode_client_frame(frame, sizeof(frame), TG_WS_BINARY,
                                     msg, sizeof(msg), &n) == 0);
    assert(n == 10 && frame[0] == 0x82 && frame[1] == 0x84);
    assert(memcmp(frame + 2, "\0\0\0\0", 4) != 0);
    for (size_t i = 0; i < sizeof(msg); ++i)
        assert(frame[6 + i] == (uint8_t)(msg[i] ^ frame[2 + i % 4]));
    assert(tg_ws_encode_client_frame(frame, 8, TG_WS_BINARY,
                                     msg, sizeof(msg), &n) != 0);
}

static void test_server_frame_bounds(void) {
    const uint8_t valid[] = {0x82,0x03,'a','b','c'};
    const uint8_t masked[] = {0x82,0x81,0,0,0,0,'x'};
    const uint8_t fragmented[] = {0x02,0x01,'x'};
    const uint8_t oversize[] = {0x82,127,0,0,0,0,0,0,0x20,0,0};
    uint8_t op;
    const uint8_t *payload;
    size_t payload_len, consumed;
    assert(tg_ws_decode_server_frame(valid, sizeof(valid), 3, &op, &payload,
                                     &payload_len, &consumed) == 0);
    assert(op == TG_WS_BINARY && payload_len == 3 && consumed == sizeof(valid));
    assert(memcmp(payload, "abc", 3) == 0);
    assert(tg_ws_decode_server_frame(masked, sizeof(masked), 10, &op, &payload,
                                     &payload_len, &consumed) != 0);
    assert(tg_ws_decode_server_frame(fragmented, sizeof(fragmented), 10, &op,
                                     &payload, &payload_len, &consumed) != 0);
    assert(tg_ws_decode_server_frame(oversize, sizeof(oversize), TG_WS_MAX_MESSAGE,
                                     &op, &payload, &payload_len, &consumed) != 0);
}

int main(void) {
    test_identity_persistence_and_signature();
    test_register_hmac_contract();
    test_nip_io_direct_ipv4();
    test_masked_client_frame();
    test_server_frame_bounds();
    puts("relay unit tests: ok");
    return 0;
}
