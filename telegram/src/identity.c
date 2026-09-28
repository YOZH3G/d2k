#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ID_FILE_LEN 88u
static const uint8_t id_magic[8] = {'D','2','K','T','G','I','D','1'};
static const char hex_digits[] = "0123456789abcdef";

static int read_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void set_hex_id(char out[33], const uint8_t id[16]) {
    for (size_t i = 0; i < 16; ++i) {
        out[2*i] = hex_digits[id[i] >> 4];
        out[2*i + 1] = hex_digits[id[i] & 15];
    }
    out[32] = '\0';
}

static int save_identity(const char *path, const uint8_t raw[ID_FILE_LEN]) {
    char tmp[4096], dir[4096];
    const char *slash;
    int fd = -1, dfd = -1, result = -1;
    size_t plen = strlen(path);
    if (plen + sizeof(".tmp.XXXXXX") > sizeof(tmp)) return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    fd = mkstemp(tmp);
    if (fd < 0) return -1;
    if (fchmod(fd, 0600) != 0 || write_all(fd, raw, ID_FILE_LEN) != 0 || fsync(fd) != 0)
        goto done;
    if (close(fd) != 0) { fd = -1; goto done; }
    fd = -1;
    if (rename(tmp, path) != 0) goto done;
    slash = strrchr(path, '/');
    if (slash) {
        size_t dlen = slash == path ? 1 : (size_t)(slash - path);
        if (dlen >= sizeof(dir)) goto done;
        memcpy(dir, path, dlen); dir[dlen] = '\0';
    } else strcpy(dir, ".");
    dfd = open(dir, O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
    result = 0;
done:
    if (fd >= 0) close(fd);
    if (result != 0) unlink(tmp);
    return result;
}

static int load_identity(const char *path, tg_identity *out) {
    uint8_t raw[ID_FILE_LEN], pub[32];
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != ID_FILE_LEN ||
        (st.st_mode & 077) != 0 || st.st_uid != geteuid() ||
        read_all(fd, raw, sizeof(raw)) != 0) {
        close(fd); return -1;
    }
    close(fd);
    if (memcmp(raw, id_magic, sizeof(id_magic)) != 0) return -1;
    out->private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw + 24, 32);
    if (!out->private_key) return -1;
    size_t pub_len = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(out->private_key, pub, &pub_len) != 1 ||
        pub_len != sizeof(pub) || memcmp(pub, raw + 56, sizeof(pub)) != 0) {
        EVP_PKEY_free(out->private_key); out->private_key = NULL; return -1;
    }
    set_hex_id(out->install_id_hex, raw + 8);
    return 0;
}

int tg_identity_load_or_mint(const char *path, tg_identity *out) {
    uint8_t raw[ID_FILE_LEN];
    EVP_PKEY_CTX *ctx = NULL;
    size_t priv_len = 32, pub_len = 32;
    if (!path || !out || strlen(path) > 4000) return -1;
    memset(out, 0, sizeof(*out));
    if (load_identity(path, out) == 0) return 0;
    memset(raw, 0, sizeof(raw));
    memcpy(raw, id_magic, sizeof(id_magic));
    if (RAND_bytes(raw + 8, 16) != 1) return -1;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_keygen(ctx, &out->private_key) != 1) goto fail;
    if (EVP_PKEY_get_raw_private_key(out->private_key, raw + 24, &priv_len) != 1 ||
        priv_len != 32 || EVP_PKEY_get_raw_public_key(out->private_key, raw + 56,
                                                     &pub_len) != 1 || pub_len != 32)
        goto fail;
    if (save_identity(path, raw) != 0) goto fail;
    set_hex_id(out->install_id_hex, raw + 8);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(raw + 24, 32);
    return 0;
fail:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(out->private_key); out->private_key = NULL;
    OPENSSL_cleanse(raw, sizeof(raw));
    return -1;
}

void tg_identity_cleanup(tg_identity *identity) {
    if (!identity) return;
    EVP_PKEY_free(identity->private_key);
    OPENSSL_cleanse(identity, sizeof(*identity));
}

int tg_identity_public_key(const tg_identity *identity, uint8_t out[32]) {
    size_t len = 32;
    if (!identity || !identity->private_key || !out ||
        EVP_PKEY_get_raw_public_key(identity->private_key, out, &len) != 1 || len != 32)
        return -1;
    return 0;
}

int tg_identity_sign(const tg_identity *identity, const uint8_t *message,
                    size_t message_len, uint8_t signature[64]) {
    EVP_MD_CTX *ctx;
    size_t len = 64;
    int ok;
    if (!identity || !identity->private_key || (!message && message_len) || !signature)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, identity->private_key) == 1 &&
         EVP_DigestSign(ctx, signature, &len, message, message_len) == 1 && len == 64;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int tg_identity_verify(const uint8_t public_key[32], const uint8_t *message,
                      size_t message_len, const uint8_t signature[64]) {
    EVP_PKEY *key;
    EVP_MD_CTX *ctx;
    int ok;
    if (!public_key || (!message && message_len) || !signature) return -1;
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
    ctx = EVP_MD_CTX_new();
    if (!key || !ctx) { EVP_PKEY_free(key); EVP_MD_CTX_free(ctx); return -1; }
    ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
         EVP_DigestVerify(ctx, signature, 64, message, message_len) == 1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

int tg_register_hmac_hex(const char *secret, const void *body, size_t body_len,
                         char out_hex[65]) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!secret || !*secret || (!body && body_len) || !out_hex ||
        !HMAC(EVP_sha256(), secret, (int)strlen(secret), body, body_len,
              digest, &digest_len) || digest_len != 32) return -1;
    for (size_t i = 0; i < digest_len; ++i) {
        out_hex[2*i] = hex_digits[digest[i] >> 4];
        out_hex[2*i + 1] = hex_digits[digest[i] & 15];
    }
    out_hex[64] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}
