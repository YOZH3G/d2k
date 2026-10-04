#define _POSIX_C_SOURCE 200809L
#include "d2k_update.h"
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* Redirects are followed manually: policy is checked before any next request. */
static int allowed(d2ku_ctx *ctx, const char *url) {
    CURLU *u = curl_url();
    char *scheme = NULL, *host = NULL, *user = NULL, *password = NULL, *fragment = NULL;
    int ok = 0;
    if (!u)
        return 0;
    if (curl_url_set(u, CURLUPART_URL, url, 0) != CURLUE_OK)
        goto done;
    if (curl_url_get(u, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK || strcmp(scheme, "https"))
        goto done;
    if (curl_url_get(u, CURLUPART_HOST, &host, 0) != CURLUE_OK)
        goto done;
    if (curl_url_get(u, CURLUPART_USER, &user, 0) == CURLUE_OK ||
        curl_url_get(u, CURLUPART_PASSWORD, &password, 0) == CURLUE_OK ||
        curl_url_get(u, CURLUPART_FRAGMENT, &fragment, 0) == CURLUE_OK)
        goto done;
    for (size_t i = 0; i < ctx->transport_host_count; i++)
        if (strnlen(ctx->transport_hosts[i], D2KU_HOST_MAX + 1) <= D2KU_HOST_MAX &&
            !strcasecmp(host, ctx->transport_hosts[i])) {
            ok = 1;
            break;
        }
done:
    curl_free(scheme);
    curl_free(host);
    curl_free(user);
    curl_free(password);
    curl_free(fragment);
    curl_url_cleanup(u);
    return ok;
}
typedef struct {
    CURL *curl;
    int fd;
    uint64_t max, written;
    size_t headers;
    d2ku_rc failure;
    char location[4096];
} download;
static size_t headers(char *data, size_t size, size_t count, void *arg) {
    download *d = arg;
    if (size && count > SIZE_MAX / size) {
        d->failure = D2KU_INVALID;
        return 0;
    }
    size_t n = size * count;
    if (n > 65536 - d->headers) {
        d->failure = D2KU_INVALID;
        return 0;
    }
    d->headers += n;
    if (n >= 5 && !memcmp(data, "HTTP/", 5))
        d->location[0] = 0;
    if (n >= 9 && !strncasecmp(data, "Location:", 9)) {
        const char *p = data + 9, *end = data + n;
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        while (end > p && (end[-1] == '\r' || end[-1] == '\n' || end[-1] == ' ' || end[-1] == '\t'))
            end--;
        size_t len = (size_t)(end - p);
        if (!len || len >= sizeof(d->location) || d->location[0] || memchr(p, 0, len)) {
            d->failure = D2KU_INVALID;
            return 0;
        }
        memcpy(d->location, p, len);
        d->location[len] = 0;
    }
    if (n >= 17 && !strncasecmp(data, "Content-Encoding:", 17)) {
        const char *p = data + 17, *end = data + n;
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        while (end > p && (end[-1] == '\r' || end[-1] == '\n' || end[-1] == ' ' || end[-1] == '\t'))
            end--;
        if (end - p != 8 || strncasecmp(p, "identity", 8)) {
            d->failure = D2KU_INVALID;
            return 0;
        }
    }
    if (n >= 15 && !strncasecmp(data, "Content-Length:", 15)) {
        const char *p = data + 15, *end = data + n;
        uint64_t v = 0;
        while (p < end && (*p == ' ' || *p == '\t'))
            p++;
        int digits = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            unsigned x = (unsigned)(*p++ - '0');
            if (v > (UINT64_MAX - x) / 10) {
                d->failure = D2KU_INVALID;
                return 0;
            }
            v = v * 10 + x;
            digits = 1;
        }
        long status = 0;
        curl_easy_getinfo(d->curl, CURLINFO_RESPONSE_CODE, &status);
        if (!digits || (status == 200 && v > d->max)) {
            d->failure = D2KU_INVALID;
            return 0;
        }
    }
    return n;
}
static size_t body(char *data, size_t size, size_t count, void *arg) {
    download *d = arg;
    long status = 0;
    if (size && count > SIZE_MAX / size) {
        d->failure = D2KU_INVALID;
        return 0;
    }
    size_t n = size * count;
    curl_easy_getinfo(d->curl, CURLINFO_RESPONSE_CODE, &status);
    /* Abort unwanted response bodies; redirect metadata has already arrived. */
    if (status != 200)
        return 0;
    if ((uint64_t)n > d->max - d->written) {
        d->failure = D2KU_INVALID;
        return 0;
    }
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(d->fd, data + off, n - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0) {
            d->failure = D2KU_IO;
            return 0;
        }
        off += (size_t)w;
    }
    d->written += n;
    return n;
}
d2ku_rc d2ku_fetch(d2ku_ctx *ctx, const char *url, int out_fd, uint64_t max_bytes) {
    struct stat st;
    d2ku_rc rc = D2KU_NETWORK;
    char *current = NULL;
    CURL *c = NULL;
    if (!ctx || !url || !max_bytes || fstat(out_fd, &st) || !S_ISREG(st.st_mode) || st.st_size ||
        st.st_nlink != 1 || lseek(out_fd, 0, SEEK_CUR) != 0)
        return D2KU_INVALID;
    int flags = fcntl(out_fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) == O_RDONLY || (flags & O_APPEND))
        return D2KU_INVALID;
    if (!ctx->transport_host_count || ctx->transport_host_count > D2KU_HOSTS_MAX ||
        !allowed(ctx, url))
        return D2KU_UNTRUSTED;
    if (!ctx->ca_bundle[0] ||
        strnlen(ctx->ca_bundle, sizeof(ctx->ca_bundle)) >= sizeof(ctx->ca_bundle) ||
        stat(ctx->ca_bundle, &st) || !S_ISREG(st.st_mode) || !st.st_size ||
        access(ctx->ca_bundle, R_OK))
        return D2KU_UNTRUSTED;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return D2KU_NETWORK;
    current = strdup(url);
    c = curl_easy_init();
    if (!current || !c) {
        rc = D2KU_IO;
        goto done;
    }
    for (unsigned redirects = 0;; redirects++) {
        download d = {.curl = c, .fd = out_fd, .max = max_bytes, .failure = D2KU_OK};
        curl_easy_reset(c);
#define SET(option, value)                                                                         \
    do {                                                                                           \
        if (curl_easy_setopt(c, option, value) != CURLE_OK)                                        \
            goto done;                                                                             \
    } while (0)
        SET(CURLOPT_URL, current);
        SET(CURLOPT_PROTOCOLS_STR, "https");
        SET(CURLOPT_REDIR_PROTOCOLS_STR, "https");
        SET(CURLOPT_FOLLOWLOCATION, 0L);
        SET(CURLOPT_PROXY, "");
        SET(CURLOPT_NOSIGNAL, 1L);
        SET(CURLOPT_SSL_VERIFYPEER, 1L);
        SET(CURLOPT_SSL_VERIFYHOST, 2L);
        SET(CURLOPT_CAINFO, ctx->ca_bundle);
        /* No compiled default CA directory or platform store may supplement policy. */
        SET(CURLOPT_CAPATH, NULL);
        SET(CURLOPT_SSL_OPTIONS, 0L);
        SET(CURLOPT_CONNECTTIMEOUT, 15L);
        SET(CURLOPT_LOW_SPEED_LIMIT, 1L);
        SET(CURLOPT_LOW_SPEED_TIME, 30L);
        SET(CURLOPT_HTTP_CONTENT_DECODING, 0L);
        SET(CURLOPT_WRITEFUNCTION, body);
        SET(CURLOPT_WRITEDATA, &d);
        SET(CURLOPT_HEADERFUNCTION, headers);
        SET(CURLOPT_HEADERDATA, &d);
#undef SET
        CURLcode result = curl_easy_perform(c);
        long status = 0;
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
        if (d.failure != D2KU_OK) {
            rc = d.failure;
            break;
        }
        if (result == CURLE_PEER_FAILED_VERIFICATION || result == CURLE_SSL_CACERT_BADFILE) {
            rc = D2KU_UNTRUSTED;
            break;
        }
        if ((status == 301 || status == 302 || status == 303 || status == 307 || status == 308) &&
            (result == CURLE_OK || result == CURLE_WRITE_ERROR)) {
            char *next = NULL;
            CURLU *u = curl_url();
            if (u && d.location[0] && curl_url_set(u, CURLUPART_URL, current, 0) == CURLUE_OK &&
                curl_url_set(u, CURLUPART_URL, d.location, 0) == CURLUE_OK)
                curl_url_get(u, CURLUPART_URL, &next, 0);
            curl_url_cleanup(u);
            if (!next || !allowed(ctx, next)) {
                curl_free(next);
                rc = D2KU_UNTRUSTED;
                break;
            }
            if (redirects == 5) {
                curl_free(next);
                rc = D2KU_NETWORK;
                break;
            }
            char *copy = strdup(next);
            curl_free(next);
            if (!copy) {
                rc = D2KU_IO;
                break;
            }
            free(current);
            current = copy;
            continue;
        }
        rc = result == CURLE_OK && status == 200 ? D2KU_OK : D2KU_NETWORK;
        break;
    }
done:
    curl_easy_cleanup(c);
    curl_global_cleanup();
    free(current);
    if (rc != D2KU_OK && (ftruncate(out_fd, 0) || lseek(out_fd, 0, SEEK_SET) < 0))
        return D2KU_IO;
    return rc;
}
d2ku_rc d2ku_verify_selected_manifest(d2ku_ctx *ctx, const d2ku_index *chosen, const void *bytes,
                                      size_t len, const unsigned char sig[64], d2ku_manifest *out) {
    unsigned char hash[32];
    unsigned int n = 0;
    if (!ctx || !chosen || !bytes || !sig || !out || len > D2KU_MANIFEST_MAX ||
        !chosen->release_id_len || chosen->release_id_len > D2KU_ID_MAX)
        return D2KU_INVALID;
    if (EVP_Digest(bytes, len, hash, &n, EVP_sha256(), NULL) != 1 || n != 32)
        return D2KU_IO;
    if (CRYPTO_memcmp(hash, chosen->manifest_sha256, 32))
        return D2KU_UNTRUSTED;
    d2ku_manifest *candidate = calloc(1, sizeof(*candidate));
    if (!candidate)
        return D2KU_IO;
    d2ku_rc rc = d2ku_verify_manifest(ctx, bytes, len, sig, candidate);
    if (rc == D2KU_OK || (rc == D2KU_INCOMPATIBLE && candidate->schema == 1)) {
        if (candidate->release_id_len != chosen->release_id_len ||
            memcmp(candidate->release_id, chosen->release_id, chosen->release_id_len))
            rc = D2KU_UNTRUSTED;
        else
            *out = *candidate;
    }
    free(candidate);
    return rc;
}
