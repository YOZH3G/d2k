#ifndef D2K_TG_IDENTITY_H
#define D2K_TG_IDENTITY_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

typedef struct {
    char install_id_hex[33];
    EVP_PKEY *private_key;
} tg_identity;

int tg_identity_load_or_mint(const char *path, tg_identity *out);
void tg_identity_cleanup(tg_identity *identity);
int tg_identity_public_key(const tg_identity *identity, uint8_t out[32]);
int tg_identity_sign(const tg_identity *identity, const uint8_t *message,
                    size_t message_len, uint8_t signature[64]);
int tg_identity_verify(const uint8_t public_key[32], const uint8_t *message,
                      size_t message_len, const uint8_t signature[64]);
int tg_register_hmac_hex(const char *secret, const void *body, size_t body_len,
                         char out_hex[65]);

#endif
