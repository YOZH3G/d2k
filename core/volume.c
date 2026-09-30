/* volume.c — направленные измерения объёма. См. d2k_volume.h.
 *
 * ЛЕСТНИЦА ИСХОДЯЩЕГО ОБЪЁМА: десять запросов по одному соединению, со второго
 * — с мусорным заголовком. Мусор в заголовке остаётся единственным способом
 * накачать соединение СВОИМ объёмом, не завися от того, что отдаёт мишень.
 *
 * Отдельная RX-пара identity/gzip ниже измеряет тело ответа и требует двух
 * совпавших обрывов плюс полного gzip-контроля. Направления не смешиваются:
 * TX-ступень и RX-обрыв возвращаются отдельными полями и попадают в каталог
 * под разными видами приметы.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"   /* d2k_mark_hook — метка ставится тем же путём, что везде */
#include "d2k_catalog.h" /* общий допуск для сопоставления RX-объёмов */
#include "d2k_tls13.h"
#include "d2k_tls12.h"
#include "d2k_volume.h"
#include "d2k_verify.h"

/* Восемь секунд на подключение и на рукопожатие — из пробы донора
   (z2k-detect/internal/tcp16), замер на этой линии. */
#define CONNECT_MS   8000
#define HANDSHAKE_MS 8000

/* Пауза между запросами. Без неё десять запросов уходят одной очередью, и
   коробка видит поток иначе, чем видит его браузер: вердикт плывёт. */
#define CHUNK_DELAY_MS 50
#define RESPONSE_PROBE_GAP_MS 500

/* Ожидание ответа считается от ИЗМЕРЕННОГО RTT, а не берётся с потолка. Живой
   ответ приходит за один RTT; «нет ответа» — это неподходящее имя, на котором
   коробка молчит, и с фиксированным потолком каждый мимо-кандидат стоил бы
   полные секунды. Нижняя граница защищает от слишком оптимистичного замера на
   первом пакете, верхняя — от линии с большим RTT. */
#define READ_MIN_MS  1500
#define READ_MAX_MS  12000

int d2k_volume_rx_partial(const d2k_ver_result *r) {
    return r && r->status >= 200 && r->status < 300 && !r->body_complete &&
        r->body_encoding == 0 && r->body_framing_valid &&
        r->body_has_length != r->body_chunked &&
        r->body_bytes >= (uint64_t)D2K_VOL_MIN_KB * 1024 &&
        (!r->body_has_length || r->body_expected > r->body_bytes);
}

int d2k_volume_rx_evidence(const d2k_ver_result *a,
                           const d2k_ver_result *b,
                           const d2k_ver_result *gzip,
                           d2k_vol_result *out) {
    const uint64_t min_bytes = (uint64_t)D2K_VOL_MIN_KB * 1024;
    if (!a || !b || !gzip || !out) { return 0; }
    if (a->status < 200 || a->status >= 300 || b->status < 200 || b->status >= 300 ||
        a->body_complete || b->body_complete || a->body_encoding != 0 ||
        !a->body_framing_valid || !b->body_framing_valid ||
        b->body_encoding != 0 || a->body_bytes < min_bytes || b->body_bytes < min_bytes ||
        a->body_has_length != b->body_has_length || a->body_chunked != b->body_chunked ||
        (!a->body_has_length && !a->body_chunked) ||
        (a->body_has_length && a->body_chunked)) { return 0; }
    if (a->body_has_length && (a->body_expected <= a->body_bytes ||
                               b->body_expected <= b->body_bytes)) { return 0; }
    uint64_t delta = a->body_bytes > b->body_bytes
                   ? a->body_bytes - b->body_bytes : b->body_bytes - a->body_bytes;
    if (delta > (uint64_t)D2K_VOLUME_SLACK * 1024) { return 0; }
    if (gzip->status < 200 || gzip->status >= 300 || !gzip->body_framing_valid ||
        !gzip->body_complete ||
        gzip->body_encoding != 1 || gzip->body_bytes == 0) { return 0; }

    out->rx_cut = 1;
    uint64_t midpoint = (a->body_bytes < b->body_bytes ? a->body_bytes : b->body_bytes)
                      + delta / 2;
    uint64_t cut_kb = midpoint / 1024;
    out->rx_at_kb = cut_kb > INT_MAX ? INT_MAX : (int)cut_kb;
    out->rx_expected_kb = 0;
    if (a->body_has_length && a->body_expected <= (uint64_t)INT_MAX * 1024) {
        out->rx_expected_kb = (int)(a->body_expected / 1024);
    }
    out->rx_compressed_complete = 1;
    if (out->rx_expected_kb > 0) {
        snprintf(out->reason, sizeof out->reason,
                 "identity-тело повторно оборвалось около %d/%d КБ; gzip завершился",
                 out->rx_at_kb, out->rx_expected_kb);
    } else {
        snprintf(out->reason, sizeof out->reason,
                 "chunked identity-тело повторно оборвалось около %d КБ; gzip завершился",
                 out->rx_at_kb);
    }
    return 1;
}

const char *d2k_vol_verdict_name(d2k_vol_verdict v) {
    switch (v) {
    case D2K_VOL_CUT:    return "обрыв по объёму";
    case D2K_VOL_PASSED: return "объём прошёл";
    case D2K_VOL_SHORT:  return "объём не набран — вердикта нет";
    default:             return "мишень не ответила";
    }
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void nap_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

static int clamp_ms(int64_t v, int lo, int hi) {
    if (v < lo) { return lo; }
    if (v > hi) { return hi; }
    return (int)v;
}

/* Набивка: печатные символы, потому что она едет в ЗАГОЛОВКЕ HTTP, а туда
   произвольные байты класть нельзя — сервер отверг бы запрос, и мы мерили бы
   это вместо блока. Из /dev/urandom, а не постоянная строка: одинаковый мусор
   в десяти запросах коробка вправе схлопнуть как повтор. */
static void fill_pad(char *out, size_t n) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    FILE *f = fopen("/dev/urandom", "rb");
    for (size_t i = 0; i < n; i++) {
        int c = f ? fgetc(f) : -1;
        if (c < 0) { c = (int)(i * 31 + 7); }
        out[i] = alphabet[(unsigned)c % (sizeof alphabet - 1)];
    }
    if (f) { fclose(f); }
}

static int connect_bounded(const char *ip, uint16_t port, uint32_t mark,
                           char *reason, size_t cap) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(reason, cap, "сокет: %s", strerror(errno)); return -1; }
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    if (mark != 0 && d2k_mark_hook(fd, mark) != 0) {
        /* Метка не поставилась — проба пойдёт ПО ОБЩИМ ПРАВИЛАМ, то есть
           через уже поставленный план. Это меряло бы работу плана, а не линию,
           и молча так делать нельзя. */
        snprintf(reason, cap, "метка 0x%x не поставилась: %s", (unsigned)mark, strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        snprintf(reason, cap, "адрес \"%s\" не разбирается", ip);
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        snprintf(reason, cap, "неблокирующий режим: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        if (errno != EINPROGRESS) {
            snprintf(reason, cap, "нет TCP: %s", strerror(errno));
            close(fd);
            return -1;
        }
        struct pollfd p;
        p.fd = fd; p.events = POLLOUT; p.revents = 0;
        if (poll(&p, 1, CONNECT_MS) <= 0) {
            snprintf(reason, cap, "нет TCP: не подключились за %d мс", CONNECT_MS);
            close(fd);
            return -1;
        }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
            snprintf(reason, cap, "нет TCP: %s", strerror(soerr ? soerr : errno));
            close(fd);
            return -1;
        }
    }
    (void)fcntl(fd, F_SETFL, flags);
    return fd;
}

/* Читает заголовки ответа до пустой строки. 0 — прочитано, -1 — обрыв. */
static int drain_head_tls(d2k_tls *t, d2k_tls12 *t12, int wait_ms, char *reason, size_t cap) {
    char line[4096];
    size_t n = 0;
    int seen_cr = 0;
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        int64_t left = deadline - now_ms();
        if (left <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        uint8_t c;
        long r = t12 ? d2k_tls12_read(t12, &c, 1, (int)left, reason, cap)
                     : d2k_tls_read(t, &c, 1, (int)left, reason, cap);
        if (r <= 0) {
            if (r == 0) { snprintf(reason, cap, "соединение закрыто"); }
            return -1;
        }
        if (c == '\n') {
            if (n == 0 || (n == 1 && seen_cr)) { return 0; } /* пустая строка */
            n = 0;
            seen_cr = 0;
            continue;
        }
        seen_cr = (c == '\r');
        if (n + 1 < sizeof line) { line[n++] = (char)c; }
    }
}

static int drain_head_plain(int fd, int wait_ms, char *reason, size_t cap) {
    size_t n = 0;
    int seen_cr = 0;
    int64_t deadline = now_ms() + wait_ms;
    for (;;) {
        if (now_ms() >= deadline) { snprintf(reason, cap, "ответа нет"); return -1; }
        struct pollfd p;
        p.fd = fd; p.events = POLLIN; p.revents = 0;
        int pr = poll(&p, 1, (int)(deadline - now_ms()));
        if (pr <= 0) { snprintf(reason, cap, "ответа нет"); return -1; }
        uint8_t c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) {
            snprintf(reason, cap, r == 0 ? "соединение закрыто" : "чтение: %s", strerror(errno));
            return -1;
        }
        if (c == '\n') {
            if (n == 0 || (n == 1 && seen_cr)) { return 0; }
            n = 0; seen_cr = 0;
            continue;
        }
        seen_cr = (c == '\r');
        n++;
    }
}

/* Входящее измерение — другой вопрос, чем лестница исходящих HEAD выше.
   Ищем воспроизводимую асимметрию: два identity-ответа с одним framing видом
   обрываются на близком объёме, а gzip-представление той же страницы доходит
   до конца. Chunked ответы допустимы: у них полного размера заранее нет.
   Ответ без Content-Length и без chunked framing не классифицируем — там
   локальный timeout нельзя отличить от конца/медленной отдачи. Все сокеты
   помечены measure_mark и не проходят через пробуемый план. */
static void probe_response_volume(d2k_vol_result *res, const char *ip,
                                  uint16_t port, const char *sni, int tls12,
                                  size_t hello_wire, uint32_t mark) {
    if (!res || !ip || !sni || !sni[0] || port == 80) { return; }
    d2k_ver_result a = d2k_verify_probe_baseline(ip, port, sni, 6000,
                                                  hello_wire, tls12, 0, mark);
    res->rx_tls_unavailable = a.level == D2K_VER_TRANSPORT && a.status == 0;
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity-1 HTTP %d, тело %llu/%llu, complete=%d: %.90s",
             a.status, (unsigned long long)a.body_bytes,
             (unsigned long long)a.body_expected, a.body_complete, a.reason);
    if (a.status < 200 || a.status >= 300 || a.body_complete || !a.body_framing_valid ||
        (!a.body_has_length && !a.body_chunked) || a.body_encoding != 0 ||
        a.body_bytes < (uint64_t)D2K_VOL_MIN_KB * 1024 ||
        (a.body_has_length && a.body_expected <= a.body_bytes)) {
        d2k_verify_close(&a);
        return;
    }
    nap_ms(RESPONSE_PROBE_GAP_MS);
    d2k_ver_result b = d2k_verify_probe_baseline(ip, port, sni, 6000,
                                                  hello_wire, tls12, 0, mark);
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity-2 HTTP %d, тело %llu/%llu, complete=%d: %.90s",
             b.status, (unsigned long long)b.body_bytes,
             (unsigned long long)b.body_expected, b.body_complete, b.reason);
    if (b.status < 200 || b.status >= 300 || b.body_complete || !b.body_framing_valid ||
        b.body_has_length != a.body_has_length || b.body_chunked != a.body_chunked ||
        b.body_encoding != 0 || b.body_bytes < (uint64_t)D2K_VOL_MIN_KB * 1024 ||
        (b.body_has_length && b.body_expected <= b.body_bytes)) {
        d2k_verify_close(&a);
        d2k_verify_close(&b);
        return;
    }
    nap_ms(RESPONSE_PROBE_GAP_MS);
    d2k_ver_result gz = d2k_verify_probe_baseline(ip, port, sni, 6000,
                                                   hello_wire, tls12, 1, mark);
    snprintf(res->rx_reason, sizeof res->rx_reason,
             "identity %llu/%llu; gzip HTTP %d, тело %llu, complete=%d, encoding=%d",
             (unsigned long long)a.body_bytes, (unsigned long long)b.body_bytes,
             gz.status, (unsigned long long)gz.body_bytes, gz.body_complete, gz.body_encoding);
    (void)d2k_volume_rx_evidence(&a, &b, &gz, res);
    d2k_verify_close(&a);
    d2k_verify_close(&b);
    d2k_verify_close(&gz);
}

d2k_vol_result d2k_volume_probe(const char *ip, uint16_t port, const char *sni,
                                int plain, int tls12, size_t hello_wire,
                                uint32_t mark) {
    d2k_vol_result res;
    memset(&res, 0, sizeof res);
    res.verdict = D2K_VOL_UNREACHABLE;
    snprintf(res.reason, sizeof res.reason, "проба не начиналась");
    if (!ip || !ip[0]) {
        snprintf(res.reason, sizeof res.reason, "адрес цели не задан");
        return res;
    }

    int64_t started = now_ms();
    int fd = connect_bounded(ip, port, mark, res.reason, sizeof res.reason);
    if (fd < 0) { return res; }

    d2k_tls *tls = NULL;
    d2k_tls12 *tls_legacy = NULL;
    if (!plain) {
        char err[160];
        const char *name = (sni && sni[0]) ? sni : NULL;
        int handshake = tls12
            ? d2k_tls12_connect(fd, name, HANDSHAKE_MS, hello_wire,
                                &tls_legacy, err, sizeof err)
            : d2k_tls_connect(fd, name, HANDSHAKE_MS, hello_wire,
                              &tls, err, sizeof err);
        if (handshake != 0) {
            /* Причина обрезается по месту, а не тянет за собой размер буфера:
               «нет TLS: » плюс хвост — читателю нужна суть, а не полный текст
               чужой ошибки (gcc ловит это как format-truncation, цель cross). */
            snprintf(res.reason, sizeof res.reason, "нет TLS: %.140s", err);
            close(fd);
            /* TX handshake failure is not a result of the independent
               GET-body measurement, which uses the client's own context. */
            probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark);
            return res;
        }
    }
    res.rtt_ms = (int)(now_ms() - started);

    const char *host = (sni && sni[0]) ? sni : ip;
    char pad[D2K_VOL_CHUNK + 1];
    fill_pad(pad, D2K_VOL_CHUNK);
    pad[D2K_VOL_CHUNK] = '\0';

    /* Пока RTT не измерен на самом запросе — ждём по потолку. */
    int read_timeout = READ_MAX_MS;

    for (int i = 0; i < D2K_VOL_STEPS; i++) {
        char req[D2K_VOL_CHUNK + 512];
        int n;
        if (i == 0) {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\n\r\n", host);
        } else {
            n = snprintf(req, sizeof req,
                         "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Connection: keep-alive\r\nX-Pad: %s\r\n\r\n", host, pad);
        }
        if (n <= 0 || (size_t)n >= sizeof req) {
            snprintf(res.reason, sizeof res.reason, "запрос не поместился");
            if (tls) { d2k_tls_free(tls); }
            if (tls_legacy) { d2k_tls12_free(tls_legacy); }
            close(fd);
            if (!plain) {
                probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark);
            }
            return res;
        }

        int sent_kb = i * D2K_VOL_CHUNK / 1024;
        int64_t req_start = now_ms();
        char err[160];
        int bad = 0;
        if (tls || tls_legacy) {
            int written = tls_legacy
                ? d2k_tls12_write(tls_legacy, (const uint8_t *)req, (size_t)n, err, sizeof err)
                : d2k_tls_write(tls, (const uint8_t *)req, (size_t)n, err, sizeof err);
            if (written != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            } else if (drain_head_tls(tls, tls_legacy, read_timeout, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            }
        } else {
            ssize_t w = send(fd, req, (size_t)n, 0);
            if (w != n) {
                snprintf(res.reason, sizeof res.reason, "запрос не ушёл: %s", strerror(errno));
                bad = 1;
            } else if (drain_head_plain(fd, read_timeout, err, sizeof err) != 0) {
                snprintf(res.reason, sizeof res.reason, "%s", err);
                bad = 1;
            }
        }
        if (bad) {
            res.at_kb = sent_kb;
            if (i == 0) {
                /* Умерли на первом же запросе — мишень недоступна, а не блок. */
                res.verdict = D2K_VOL_UNREACHABLE;
            } else if (sent_kb >= D2K_VOL_MIN_KB) {
                res.verdict = D2K_VOL_CUT;
            } else {
                res.verdict = D2K_VOL_SHORT;
            }
            if (tls) { d2k_tls_free(tls); }
            if (tls_legacy) { d2k_tls12_free(tls_legacy); }
            close(fd);
            if (!plain) {
                probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark);
            }
            return res;
        }
        if (i == 0) {
            /* RTT известен — дальше ждём втрое дольше него, в разумных
               границах: «нет ответа» распознаётся втрое быстрее прежнего. */
            read_timeout = clamp_ms((now_ms() - req_start) * 3, READ_MIN_MS, READ_MAX_MS);
        }
        nap_ms(CHUNK_DELAY_MS);
    }

    res.verdict = D2K_VOL_PASSED;
    res.at_kb = D2K_VOL_STEPS * D2K_VOL_CHUNK / 1024;
    snprintf(res.reason, sizeof res.reason, "лестница пройдена целиком");
    if (tls) { d2k_tls_free(tls); }
    if (tls_legacy) { d2k_tls12_free(tls_legacy); }
    close(fd);
    if (!plain) {
        probe_response_volume(&res, ip, port, sni, tls12, hello_wire, mark);
    }
    return res;
}
