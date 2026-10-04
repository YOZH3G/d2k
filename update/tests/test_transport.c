#define _POSIX_C_SOURCE 200809L
#include "d2k_update.h"
#include <assert.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int64_t now = 150;
static d2ku_rc wall(void *arg, int64_t *out) {
    (void)arg;
    *out = now;
    return D2KU_OK;
}
static void binding(d2ku_ctx *ctx) {
    const char *json = "{\"schema\":1,\"release_id\":\"r2\",\"version\":\"v2\",\"commit\":"
                       "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"built_at\":100,\"notes\":"
                       "\"\",\"min_updater\":1,\"wire\":1,\"state\":1,\"packages\":[{\"abi\":"
                       "\"arm64\",\"artifact\":\"a.tar\",\"size\":2048,\"sha256\":"
                       "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                       "\"files\":[{\"path\":\"bin/"
                       "a\",\"size\":3,\"mode\":493,\"sha256\":"
                       "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}]}]}";
    unsigned char seed[32] = {7}, sig[64];
    size_t n = 32;
    unsigned int hn;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    assert(key);
    ctx->trust_count = 1;
    ctx->trust[0].not_before = 50;
    ctx->trust[0].not_after = 250;
    assert(EVP_PKEY_get_raw_public_key(key, ctx->trust[0].public_key, &n) == 1);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    n = 64;
    assert(md && EVP_DigestSignInit(md, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestSign(md, sig, &n, (const unsigned char *)json, strlen(json)) == 1);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    ctx->clock.wall = wall;
    strcpy(ctx->abi, "arm64");
    ctx->updater_version = ctx->wire_version = ctx->state_version = 1;
    d2ku_index idx = {0};
    strcpy(idx.release_id, "r2");
    idx.release_id_len = 2;
    assert(EVP_Digest(json, strlen(json), idx.manifest_sha256, &hn, EVP_sha256(), NULL) == 1);
    d2ku_manifest *out = malloc(sizeof(*out));
    assert(out);
    assert(d2ku_verify_selected_manifest(ctx, &idx, json, strlen(json), sig, out) == D2KU_OK);
    idx.manifest_sha256[0] ^= 1;
    memset(out, 0xa5, sizeof(*out));
    assert(d2ku_verify_selected_manifest(ctx, &idx, json, strlen(json), sig, out) ==
           D2KU_UNTRUSTED);
    assert(out->schema == UINT64_C(0xa5a5a5a5a5a5a5a5));
    idx.manifest_sha256[0] ^= 1;
    strcpy(idx.release_id, "r1");
    assert(d2ku_verify_selected_manifest(ctx, &idx, json, strlen(json), sig, out) ==
           D2KU_UNTRUSTED);
    assert(out->schema == UINT64_C(0xa5a5a5a5a5a5a5a5));
    strcpy(idx.release_id, "r2");
    ctx->wire_version = 2;
    assert(d2ku_verify_selected_manifest(ctx, &idx, json, strlen(json), sig, out) ==
           D2KU_INCOMPATIBLE);
    assert(!strcmp(out->version, "v2"));
    free(out);
}
int main(int argc, char **argv) {
    assert(argc == 4);
    d2ku_ctx ctx = {0};
    strcpy(ctx.transport_hosts[0], "localhost");
    ctx.transport_host_count = 1;
    assert(strlen(argv[2]) < sizeof(ctx.ca_bundle));
    strcpy(ctx.ca_bundle, argv[2]);
    char path[512], url[1024];
    snprintf(path, sizeof(path), "%s/out", argv[3]);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(fd >= 0);
    struct {
        const char *path;
        uint64_t max;
        d2ku_rc rc;
    } cases[] = {{"/ok", 3, D2KU_OK},
                 {"/bad-tls", 3, D2KU_UNTRUSTED},
                 {"/wrong-name", 3, D2KU_UNTRUSTED},
                 {"/redirect-http", 100, D2KU_UNTRUSTED},
                 {"/redirect-host", 100, D2KU_UNTRUSTED},
                 {"/redirect-good", 3, D2KU_OK},
                 {"/redirect-five", 3, D2KU_OK},
                 {"/loop", 3, D2KU_NETWORK},
                 {"/large", 3, D2KU_INVALID},
                 {"/chunked", 3, D2KU_INVALID},
                 {"/error", 3, D2KU_NETWORK},
                 {"/compressed", 100, D2KU_INVALID},
                 {"/creds", 3, D2KU_UNTRUSTED}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
        snprintf(url, sizeof(url), "%s%s", argv[1], cases[i].path);
        d2ku_rc rc = d2ku_fetch(&ctx, url, fd, cases[i].max);
        if (rc != cases[i].rc)
            fprintf(stderr, "%s rc=%d expected=%d\n", cases[i].path, rc, cases[i].rc);
        assert(rc == cases[i].rc);
        struct stat st;
        assert(fstat(fd, &st) == 0);
        if (rc != D2KU_OK)
            assert(st.st_size == 0);
        else {
            char b[4] = {0};
            assert(pread(fd, b, 3, 0) == 3 && !strcmp(b, "abc"));
        }
    }
    assert(ftruncate(fd, 0) == 0);
    snprintf(url, sizeof(url), "%s/ok", argv[1]);
    strcpy(ctx.ca_bundle, "/missing/d2ku-ca");
    assert(d2ku_fetch(&ctx, url, fd, 3) == D2KU_UNTRUSTED);
    strcpy(ctx.ca_bundle, argv[2]);
    ctx.transport_host_count = 0;
    assert(d2ku_fetch(&ctx, url, fd, 3) == D2KU_UNTRUSTED);
    ctx.transport_host_count = 1;
    assert(d2ku_fetch(&ctx, "http://localhost/ok", fd, 3) == D2KU_UNTRUSTED);
    assert(d2ku_fetch(&ctx, "https://user:pass@localhost/ok", fd, 3) == D2KU_UNTRUSTED);
    assert(write(fd, "old", 3) == 3);
    assert(d2ku_fetch(&ctx, url, fd, 3) == D2KU_INVALID);
    char b[4] = {0};
    assert(pread(fd, b, 3, 0) == 3 && !strcmp(b, "old"));
    close(fd);
    assert(unlink(path) == 0);
    binding(&ctx);
    puts("transport: real TLS, redirects, bounds and selected manifest binding OK");
    return 0;
}
