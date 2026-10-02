/* Exercise the production HTTP reader with fragmented byte streams, no sockets. */
#include "verify.c"
#include <stdio.h>

typedef struct { const char *reply; size_t pos, fragment; } fixture;
static long fixture_read(void *ctx, uint8_t *buf, size_t cap, int wait,
                         char *err, size_t errcap) {
    fixture *f = ctx;
    (void)wait; (void)err; (void)errcap;
    size_t n = strlen(f->reply) - f->pos;
    if (n > cap) n = cap;
    if (n > f->fragment) n = f->fragment;
    memcpy(buf, f->reply + f->pos, n); f->pos += n;
    return (long)n;
}
static int fixture_write(void *ctx, const uint8_t *buf, size_t n,
                         char *err, size_t errcap) {
    (void)ctx; (void)buf; (void)n; (void)err; (void)errcap;
    return 0;
}
int main(void) {
    struct { const char *reply; d2k_ver_level level; } cases[] = {
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nContent-Length: 0\r\n\r\n", D2K_VER_APPLICATION},
        {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 302 Found\r\nLocation: //eais.rkn.gov.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n7\r\naccess \r\nE\r\nblocked by rkn\r\n0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 403 Forbidden\r\nLink: <https://eais.rkn.gov.ru/>\r\nContent-Length: 0\r\n\r\n", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nok", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 451 Unavailable\r\nContent-Length: 0\r\n\r\n", D2K_VER_DENIED},
        {"HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_CHALLENGE},
        {"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nContent-Length: 20\r\n\r\nshort", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 14\r\n", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\neais.rkn.gov.ru", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 30\r\n\r\neais.rkn.gov.ru", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\nLocation: https://www.google.com/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nLocation: https://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_HANDSHAKE},
        {"HTTP/1.1 451 Unavailable\r\nContent-Length: nope\r\n\r\n", D2K_VER_DENIED},
        {"HTTP/1.1 451 Unavailable\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\n", D2K_VER_DENIED},
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        for (size_t fragment = 1; fragment <= 512; fragment *= 8) {
            fixture f = {cases[i].reply, 0, fragment};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE; r.name_ok = 0;
            request_complete_page(fixture_read, fixture_write, &f, "googlevideo.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            if (r.level != cases[i].level || r.name_ok != 0) {
                fprintf(stderr, "case %zu fragment %zu: level %d expected %d (%s)\n",
                    i, fragment, r.level, cases[i].level, r.reason); fails++;
            }
            if (i == 0) {
                fixture css = {cases[i].reply, 0, fragment};
                memset(&r, 0, sizeof r); r.level = D2K_VER_HANDSHAKE;
                request_complete_page(fixture_read, fixture_write, &css, "googlevideo.com",
                    0, "/assets/app.css", 1000, 0, &r, err, sizeof err);
                if (r.level == D2K_VER_APPLICATION) {
                    fprintf(stderr, "cross-origin redirect accepted as stylesheet\n"); fails++;
                }
            }
        }
    }
    struct { int code; d2k_ver_level before, after; } ech[] = {
        {451,D2K_VER_DENIED,D2K_VER_DENIED},
        {403,D2K_VER_BLOCKPAGE,D2K_VER_BLOCKPAGE},
        {403,D2K_VER_APPLICATION,D2K_VER_CHALLENGE},
        {200,D2K_VER_APPLICATION,D2K_VER_APPLICATION},
    };
    for (size_t i=0;i<sizeof ech/sizeof ech[0];i++) {
        d2k_ver_result r={0}; r.status=ech[i].code; r.level=ech[i].before;
        ech_http_denial(&r);
        if (r.level != ech[i].after) { fprintf(stderr,"ECH denial case %zu failed\n",i); fails++; }
    }
    if (fails) return 1;
    puts("Production HTTP reader: 76 fragments + 4 stylesheet + 4 ECH checks passed without sockets");
    return 0;
}
