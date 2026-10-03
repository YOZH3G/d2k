/* Exercise the production HTTP reader with fragmented byte streams, no sockets. */
#include "verify.c"
#include <stdio.h>

typedef struct { const char *reply; size_t pos, fragment; int eof_err; size_t len; } fixture;
static long fixture_read(void *ctx, uint8_t *buf, size_t cap, int wait,
                         char *err, size_t errcap) {
    fixture *f = ctx;
    (void)wait; (void)err; (void)errcap;
    size_t total = f->len ? f->len : strlen(f->reply);
    size_t n = total - f->pos;
    if (n == 0 && f->eof_err) return -1; /* обрыв без текста причины */
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

/* Задача 44: поток HTTP/3 с кадром HEADERS заданной длины, кусками по step. */
typedef struct { uint8_t *data; size_t len, pos, step; } h3_fixture;
static long h3_fixture_recv(void *ctx, uint8_t *buf, size_t cap, char *err, size_t errcap) {
    h3_fixture *f = ctx; (void)err; (void)errcap;
    size_t n = f->len - f->pos;
    if (n == 0) return 0;
    if (n > cap) n = cap;
    if (n > f->step) n = f->step;
    memcpy(buf, f->data + f->pos, n); f->pos += n;
    return (long)n;
}
static size_t h3_headers_frame(uint8_t *out, size_t section_len) {
    /* секция: префикс 00 00, :status 200 индексом, затем x-pad с литеральным
       именем и значением по 400 байт (7-бит длина: 0x7f 0x91 0x02) */
    size_t o = 0;
    uint8_t *sec = malloc(section_len + 16);
    size_t k = 0;
    sec[k++] = 0; sec[k++] = 0; sec[k++] = 0xd9;
    while (k + 410 < section_len) {
        sec[k++] = 0x25; memcpy(sec + k, "x-pad", 5); k += 5;
        sec[k++] = 0x7f; sec[k++] = 0x91; sec[k++] = 0x02;
        memset(sec + k, 'q', 400); k += 400;
    }
    out[o++] = 0x01;
    out[o++] = 0x80 | (uint8_t)(k >> 24); out[o++] = (uint8_t)(k >> 16);
    out[o++] = (uint8_t)(k >> 8); out[o++] = (uint8_t)k;
    memcpy(out + o, sec, k); o += k;
    free(sec);
    return o;
}
int main(void) {
    struct { const char *reply; d2k_ver_level level; } cases[] = {
        {"HTTP/1.1 302 Found\r\nLocation: https://www.google.com/\r\nContent-Length: 0\r\n\r\n", D2K_VER_APPLICATION},
        {"HTTP/1.1 302 Found\r\nLocation: https://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 302 Found\r\nLocation: //eais.rkn.gov.ru/\r\nContent-Length: 0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n7\r\naccess \r\nE\r\nblocked by rkn\r\n0\r\n\r\n", D2K_VER_BLOCKPAGE},
        {"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 21\r\n\r\naccess blocked by rkn", D2K_VER_APPLICATION},
        {"HTTP/1.1 403 Forbidden\r\nLink: <https://eais.rkn.gov.ru/>\r\nContent-Length: 0\r\n\r\n", D2K_VER_APPLICATION},
        {"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nok", D2K_VER_APPLICATION},
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
            fixture f = {cases[i].reply, 0, fragment, 0, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE; r.name_ok = 0;
            request_complete_page(fixture_read, fixture_write, &f, "googlevideo.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            if (r.level != cases[i].level || r.name_ok != 0) {
                fprintf(stderr, "case %zu fragment %zu: level %d expected %d (%s)\n",
                    i, fragment, r.level, cases[i].level, r.reason); fails++;
            }
            if (i == 0) {
                fixture css = {cases[i].reply, 0, fragment, 0, 0};
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
    /* Задача 42: этап «рукопожатие прошло, приложение молчит» назван прямо. */
    {
        d2k_ver_result r = {0};
        quic_app_silent(&r, 0, 4812, NULL);
        if (!strstr(r.reason, "рукопожатие прошло, приложение молчит, получено 0 байт") ||
            !strstr(r.reason, "4812")) {
            fprintf(stderr, "QUIC silent-application stage: %s\n", r.reason); fails++;
        }
        quic_app_silent(&r, 2337, 7170, "сервер закрыл соединение");
        if (!strstr(r.reason, "рукопожатие прошло, приложение молчит, получено 2337 байт") ||
            !strstr(r.reason, "закрыто")) {
            fprintf(stderr, "QUIC silent-application stage (closed): %s\n", r.reason); fails++;
        }
    }

    /* Задача 44: заголовки длиннее 8 КБ (поле 03.10.2026, web.whatsapp.com —
       край Meta отдаёт ~8,4 КБ заголовков) не отбраковывают рабочий обход. */
    {
        static char big[96 * 1024];
        size_t o = 0;
        o += (size_t)snprintf(big + o, sizeof big - o,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=\"utf-8\"\r\n"
            "Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n");
        const char *names[] = {"content-security-policy", "report-to",
            "set-cookie", "content-security-policy-report-only",
            "reporting-endpoints", "permissions-policy"};
        for (int k = 0; o < 8400; k++) {
            o += (size_t)snprintf(big + o, sizeof big - o, "%s: ", names[k % 6]);
            for (int j = 0; j < 400; j++) big[o++] = (char)('a' + (j * 7 + k) % 26);
            big[o++] = '\r'; big[o++] = '\n';
        }
        o += (size_t)snprintf(big + o, sizeof big - o, "\r\n");
        for (int chunk = 0; chunk < 8; chunk++) {
            o += (size_t)snprintf(big + o, sizeof big - o, "1000\r\n");
            for (int j = 0; j < 4096; j++) big[o++] = (char)('A' + j % 26);
            big[o++] = '\r'; big[o++] = '\n';
        }
        o += (size_t)snprintf(big + o, sizeof big - o, "0\r\n\r\n");
        big[o] = '\0';
        size_t frags[] = {1, 7, 1460, sizeof big};
        for (size_t k = 0; k < 4; k++) {
            fixture f = {big, 0, frags[k], 0, 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE;
            request_complete_page(fixture_read, fixture_write, &f, "web.whatsapp.com",
                2, NULL, 1000, 0, &r, err, sizeof err);
            if (r.level != D2K_VER_APPLICATION || r.status != 200 || !r.body_complete ||
                r.local_limit) {
                fprintf(stderr, "long headers, fragment %zu: level %d status %d (%s)\n",
                    frags[k], r.level, r.status, r.reason); fails++;
            }
        }
        /* Предел: заголовки больше D2K_VERIFY_HEADER_LIMIT — отказ с названием
           предела, и это наш предел, а не улика с провода. */
        static char huge[D2K_VERIFY_HEADER_LIMIT + 4096];
        size_t h = (size_t)snprintf(huge, sizeof huge, "HTTP/1.1 200 OK\r\n");
        while (h < sizeof huge - 600) {
            h += (size_t)snprintf(huge + h, sizeof huge - h, "x-pad: ");
            memset(huge + h, 'q', 400); h += 400;
            huge[h++] = '\r'; huge[h++] = '\n';
        }
        huge[h] = '\0';
        fixture hf = {huge, 0, 1460, 0, 0};
        d2k_ver_result r = {0}; char err[200] = "";
        r.level = D2K_VER_HANDSHAKE;
        request_complete_page(fixture_read, fixture_write, &hf, "web.whatsapp.com",
            2, NULL, 1000, 0, &r, err, sizeof err);
        char want[64];
        snprintf(want, sizeof want, "длиннее %d байт", D2K_VERIFY_HEADER_LIMIT);
        if (r.level == D2K_VER_APPLICATION || !strstr(r.reason, "заголовки ответа") ||
            !strstr(r.reason, want) || !r.local_limit) {
            fprintf(stderr, "header limit: level %d local %d (%s)\n",
                r.level, r.local_limit, r.reason); fails++;
        }
    }
    /* Задача 44: у каждого неуспеха чтения ответа своя непустая причина. */
    {
        struct { const char *reply; int eof_err; const char *needle; } bad[] = {
            {"SMTP/1.1 200 OK\r\n\r\n", 0, "строка статуса"},
            {"HTTP/1.1 200 O\0K\r\n\r\n", 0, "нулев"},
            {"HTTP/1.1 101 Switching\r\n\r\n", 0, "101"},
            {"", 0, "закрыл"},
            {"HTTP/1.1 200 OK\r\nX: y\r\n", 0, "закрыл"},
            {"", 1, "ошибка чтения"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            fixture f = {bad[i].reply, 0, 64, bad[i].eof_err, i == 1 ? 20 : 0};
            d2k_ver_result r = {0}; char err[200] = "";
            r.level = D2K_VER_HANDSHAKE;
            request_complete_page(fixture_read, fixture_write, &f, "example.com",
                0, NULL, 1000, 0, &r, err, sizeof err);
            const char *colon = strstr(r.reason, "ответа: ");
            if (r.level == D2K_VER_APPLICATION || !colon || colon[strlen("ответа: ")] == '\0' ||
                !strstr(r.reason, bad[i].needle) || r.local_limit) {
                fprintf(stderr, "failure reason %zu: [%s]\n", i, r.reason); fails++;
            }
        }
    }
    /* Задача 44: заголовки HTTP/3 длиннее 8 КБ разбираются; сверх предела —
       названная причина и признак нашего предела. */
    {
        static uint8_t frame[D2K_VERIFY_HEADER_LIMIT + 8192], rx[D2K_VERIFY_HEADER_LIMIT];
        size_t frames[] = {8600, 20000};
        for (size_t k = 0; k < 2; k++) {
            size_t fl = h3_headers_frame(frame, frames[k]);
            h3_fixture f = {frame, fl, 0, k ? 1460 : 1};
            size_t got = 0; int st = 0, closed = 0; char err[100] = "";
            int too_long = h3_read_headers(h3_fixture_recv, &f, rx, sizeof rx,
                verify_now_ms() + 100000, &got, &st, &closed, err, sizeof err);
            if (too_long || st != 200) {
                fprintf(stderr, "H3 headers %zu: too_long %d status %d\n", frames[k], too_long, st); fails++;
            }
        }
        size_t fl = h3_headers_frame(frame, D2K_VERIFY_HEADER_LIMIT + 4000);
        h3_fixture f = {frame, fl, 0, 4096};
        size_t got = 0; int st = 0, closed = 0; char err[100] = "";
        int too_long = h3_read_headers(h3_fixture_recv, &f, rx, sizeof rx,
            verify_now_ms() + 100000, &got, &st, &closed, err, sizeof err);
        if (!too_long || st != 0) {
            fprintf(stderr, "H3 header limit: too_long %d status %d\n", too_long, st); fails++;
        }
    }
    if (fails) return 1;
    puts("Production HTTP reader: 76 fragments + 4 stylesheet + 4 ECH + long-header (TCP 4+limit, H3 3) + 6 failure-reason checks passed without sockets");
    return 0;
}
