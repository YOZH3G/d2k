#ifndef D2K_RESOURCE_H
#define D2K_RESOURCE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Hints from OUR anonymous, identity HTML response, not from encrypted client
 * requests. They never schedule a target: only an already observed SNI may
 * use a hint. Keep just public stylesheet paths, without queries or tokens. */
#define D2K_RESOURCE_COUNT 2
typedef struct { char host[256], path[512]; } d2k_resource;
typedef struct {
    char tag[2048];
    size_t used, seen;
    int active, quote, comment, raw;
    d2k_resource refs[D2K_RESOURCE_COUNT];
    size_t count;
} d2k_resource_scan;

static inline int d2k_resource_word(const char *s, size_t n, const char *word) {
    if (strlen(word) != n) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)word[i]) return 0;
    }
    return 1;
}
static inline int d2k_resource_space(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}
static inline int d2k_resource_path_ok(const char *path) {
    size_t n = path ? strlen(path) : 0;
    if (!n || n >= 512 || path[0] != '/' || path[1] == '/' ||
        strstr(path, "/../") || strstr(path, "/./")) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)path[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '/' || c == '.' ||
              c == '-' || c == '_')) return 0;
    }
    return n >= 4 && d2k_resource_word(path + n - 4, 4, ".css");
}
static inline void d2k_resource_add(d2k_resource_scan *s, const char *url) {
    const char *host = NULL;
    if (!strncmp(url, "https://", 8)) host = url + 8;
    else if (!strncmp(url, "//", 2)) host = url + 2;
    else return; /* Relative URLs need a document base; do not guess it. */
    const char *path = strchr(host, '/');
    if (!path || !d2k_resource_path_ok(path)) return;
    size_t n = (size_t)(path - host);
    if (!n || n >= sizeof s->refs[0].host || host[0] == '.' || host[n-1] == '.') return;
    char name[256];
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)host[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return;
        name[i] = (char)c;
    }
    name[n] = 0;
    for (size_t i = 0; i < s->count; i++)
        if (!strcmp(name, s->refs[i].host)) return; /* One resource per host. */
    if (s->count == D2K_RESOURCE_COUNT) return;
    strcpy(s->refs[s->count].host, name);
    strcpy(s->refs[s->count++].path, path);
}
static inline void d2k_resource_tag(d2k_resource_scan *s) {
    char *p = s->tag;
    size_t n = strcspn(p, " \t\r\n\f/>");
    if (s->raw) {
        if ((s->raw == 1 && !strncmp(p, "/script", 7)) ||
            (s->raw == 2 && !strncmp(p, "/style", 6))) s->raw = 0;
        return;
    }
    if (d2k_resource_word(p, n, "script")) { s->raw = 1; return; }
    if (d2k_resource_word(p, n, "style")) { s->raw = 2; return; }
    if (d2k_resource_word(p, n, "body")) { s->seen = 32768; return; }
    if (!d2k_resource_word(p, n, "link")) return;
    p += n;
    char href[1024] = {0}; int stylesheet = 0, seen_href = 0, seen_rel = 0;
    while (*p) {
        while (d2k_resource_space((unsigned char)*p)) p++;
        if (!*p || *p == '/' || *p == '>') break;
        char *key = p;
        while (*p && !d2k_resource_space((unsigned char)*p) && *p != '=' && *p != '>') p++;
        size_t kn = (size_t)(p - key);
        while (d2k_resource_space((unsigned char)*p)) p++;
        if (*p != '=') { if (!kn) p++; continue; }
        p++;
        while (d2k_resource_space((unsigned char)*p)) p++;
        char quote = *p == '\'' || *p == '"' ? *p++ : 0;
        char *value = p;
        while (*p && (quote ? *p != quote : !d2k_resource_space((unsigned char)*p) && *p != '>')) p++;
        size_t vn = (size_t)(p - value);
        if (quote && *p != quote) return;
        if (quote) p++;
        if (d2k_resource_word(key, kn, "href")) {
            if (seen_href++ || vn >= sizeof href) return;
            memcpy(href, value, vn); href[vn] = 0;
        } else if (d2k_resource_word(key, kn, "rel")) {
            if (seen_rel++) return;
            stylesheet = d2k_resource_word(value, vn, "stylesheet");
        }
    }
    if (stylesheet && seen_href) d2k_resource_add(s, href);
}
static inline void d2k_resource_feed(d2k_resource_scan *s, const uint8_t *buf, size_t n) {
    if (!s) return;
    for (size_t i = 0; i < n && s->seen < 32768; i++, s->seen++) {
        unsigned char c = buf[i];
        if (!s->active) {
            if (c == '<') { s->active = 1; s->used = 0; s->quote = 0; }
            continue;
        }
        if (s->used + 1 >= sizeof s->tag) { s->active = 0; continue; }
        s->tag[s->used++] = (char)c;
        if (s->used == 3 && !memcmp(s->tag, "!--", 3)) s->comment = 1;
        if (s->comment) {
            if (s->used >= 3 && !memcmp(s->tag + s->used - 3, "-->", 3)) {
                s->active = s->comment = 0;
            }
            continue;
        }
        if (s->quote) { if (c == s->quote) s->quote = 0; continue; }
        if (c == '\'' || c == '"') { s->quote = c; continue; }
        if (c == '>') {
            s->tag[s->used - 1] = 0; d2k_resource_tag(s); s->active = 0;
        }
    }
}
#endif
