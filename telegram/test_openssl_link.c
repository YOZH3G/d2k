#include <openssl/evp.h>
#include <openssl/ssl.h>

int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    EVP_PKEY_CTX *ed = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    if (!ctx || !ed) return 1;
    EVP_PKEY_CTX_free(ed);
    SSL_CTX_free(ctx);
    return 0;
}
