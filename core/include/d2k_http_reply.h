#ifndef D2K_HTTP_REPLY_H
#define D2K_HTTP_REPLY_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef enum { D2K_HTTP_NEUTRAL, D2K_HTTP_POSITIVE,
    D2K_HTTP_BLOCKED, D2K_HTTP_LEGAL_DENIAL } d2k_http_outcome;
typedef struct { d2k_http_outcome outcome; const char *evidence; } d2k_http_reply_result;
static inline unsigned char d2k_http_lower(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 32) : c;
}
static inline int d2k_http_equal(const unsigned char *p, const char *word, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (d2k_http_lower(p[i]) != (unsigned char)word[i]) return 0;
    return 1;
}
static inline int d2k_http_hostchar(unsigned char c) {
    c = d2k_http_lower(c);
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
        c == '_' || c == '.' || c == '-';
}
static inline const char *d2k_http_portal(size_t i) {
    static const char *const hosts[] = {"eais.rkn.gov.ru", "lawfilter.ertelecom.ru",
        "blackhole.svyaztelecom.ru", "warning.rt.ru", "warn.beeline.ru", "deny.megafon.ru"};
    return hosts[i];
}
static inline const char *d2k_http_location_portal(const char *location) {
    if (!location) return NULL;
    const unsigned char *p = (const unsigned char *)location;
    size_t n = strlen(location);
    if (n >= 7 && d2k_http_equal(p, "http://", 7)) p += 7;
    else if (n >= 8 && d2k_http_equal(p, "https://", 8)) p += 8;
    else if (n >= 2 && p[0] == '/' && p[1] == '/') p += 2;
    else return NULL;
    const unsigned char *end = p;
    while (*end && *end != '/' && *end != '?' && *end != '#' && *end > 32) end++;
    for (const unsigned char *q = p; q < end; q++) if (*q == '@') p = q + 1;
    const unsigned char *colon = NULL;
    for (const unsigned char *q = p; q < end; q++) if (*q == ':') colon = q;
    if (colon && colon + 1 < end) {
        int numeric = 1;
        for (const unsigned char *q = colon + 1; q < end; q++)
            if (*q < '0' || *q > '9') numeric = 0;
        if (numeric) end = colon;
    }
    if (end > p && end[-1] == '.') end--;
    for (size_t i = 0; i < 6; i++) {
        const char *host = d2k_http_portal(i);
        if ((size_t)(end - p) == strlen(host) && d2k_http_equal(p, host, strlen(host))) return host;
    }
    return NULL;
}
/* z2k-alert.lua signatures only: ordinary WAF/errors and foreign redirects
 * are neutral. Scan bounded decoded body bytes, never headers/compressed data. */
static inline d2k_http_reply_result d2k_http_reply_classify(int code,
    const char *location, int encoding, const unsigned char *body,
    size_t length, uint64_t total) {
    d2k_http_reply_result r={D2K_HTTP_NEUTRAL,""};
    if (code == 451) { r.outcome = D2K_HTTP_LEGAL_DENIAL; r.evidence = "HTTP 451"; return r; }
    if ((code >= 200 && code < 300) || code == 304) { r.outcome = D2K_HTTP_POSITIVE; return r; }
    if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
        const char *host = d2k_http_location_portal(location);
        if (host) { r.outcome = D2K_HTTP_BLOCKED; r.evidence = host; }
        else if (location && location[0] == '/' && location[1] && location[1] != '/') r.outcome = D2K_HTTP_POSITIVE;
        return r;
    }
    if (code < 400 || code > 599 || encoding || !body) return r;
    const char *phrase = "access blocked by rkn";
    size_t pn = strlen(phrase);
    for (size_t p = 0; p + pn <= length; p++)
        if (d2k_http_equal(body + p, phrase, pn)) {
            r.outcome = D2K_HTTP_BLOCKED; r.evidence = phrase; return r;
        }
    for (size_t i = 0; i < 6; i++) {
        const char *host = d2k_http_portal(i); size_t hn = strlen(host);
        for (size_t p = 0; p + hn <= length; p++) {
            if (p && d2k_http_hostchar(body[p-1])) continue;
            if (p + hn == length && total > length) continue;
            if (p + hn < length && d2k_http_hostchar(body[p+hn])) continue;
            if (d2k_http_equal(body + p, host, hn)) {
                r.outcome = D2K_HTTP_BLOCKED; r.evidence = host; return r;
            }
        }
    }
    return r;
}
#endif
