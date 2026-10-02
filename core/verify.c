/* verify.c — зонд, читающий начало прикладного ответа. См. d2k_verify.h:
 * почему внешний тип записи 23 доказательством не является и почему повтор
 * снятого чужого приветствия рукопожатия не завершает.
 *
 * СОБИРАЕТСЯ ИЗ ГОТОВОГО, А НЕ ПИШЕТСЯ ЗАНОВО, и обе половины взяты не ради
 * экономии строк:
 *
 * 1. Обращение — d2k_props_contact (compose.c). Её две оговорки —
 *    «непомеченное» и «сокет закрывает вызывающий» — это ровно те условия,
 *    без которых измерение перестаёт измерять (см. её doc-комментарий и
 *    docs/field/2026-09-11-first-c-ask.md). Второе обращение к цели,
 *    написанное здесь рядом, разошлось бы с ним в мелочи, которая стоила бы
 *    измерения, — а расходятся такие копии молча.
 *
 * 2. Рукопожатие — d2k_tls13 (tls13.c), свой клиент TLS 1.3 на X25519 и
 *    AES-128-GCM, проверенный на живых серверах. Ключ у него СВОЙ, поэтому
 *    он может довести рукопожатие до конца и заговорить внутри сессии;
 *    снятое приветствие цели этого не может в принципе.
 *
 * ЧТО ЗДЕСЬ НЕ ПРОВЕРЯЕТСЯ: подлинность сервера. Предмет измерения — коробка
 * на линии. Поэтому результат НЕ доказывает доступность настоящего сайта:
 * HTTP мог вернуть посредник. Это ограничение нельзя переносить с объёмного
 * измерителя на достоверность обхода без отдельной проверки подлинности.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>

#include "d2k_compose_internal.h" /* d2k_props_contact — общее обращение к цели */
#include "d2k_h3.h"
#include "d2k_quicconn.h"
#include "d2k_quicprobe.h" /* D2K_QUIC_ARM_DATA_BYTES */
#include "d2k_tls13.h"
#include "d2k_tls12.h"
#include "d2k_verify.h"
#include "d2k_meas.h"

static int64_t verify_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static unsigned dns16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

/* Decode compression with an explicit jump budget; cursor follows the
 * original encoded name, never a compression pointer's destination. */
static int ech_dns_name(const uint8_t *b, size_t n, size_t *cursor,
                         char out[256]) {
    size_t p = *cursor, used = 0, after = 0;
    unsigned jumps = 0;
    while (p < n) {
        unsigned c = b[p++];
        if (!c) {
            if (!after) after = p;
            out[used] = 0; *cursor = after; return 0;
        }
        if ((c & 0xc0) == 0xc0) {
            if (p >= n || ++jumps > 16) return -1;
            if (!after) after = p + 1;
            p = ((size_t)(c & 63) << 8) | b[p];
            continue;
        }
        if (c > 63 || c > n - p || used + c + (used != 0) > 253) return -1;
        if (used) out[used++] = '.';
        for (unsigned j = 0; j < c; j++) {
            unsigned v = b[p++];
            if (v >= 'A' && v <= 'Z') v += 'a' - 'A';
            if (!((v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '-')) return -1;
            out[used++] = (char)v;
        }
    }
    return -1;
}

int d2k_ech_resolve(const char *origin, uint32_t mark, d2k_ech_config *config) {
    if (!origin || !config || !origin[0] || strlen(origin) > 253) return -1;
    char expected[256];
    uint8_t query[512] = {0}, reply[4096];
    if (d2k_t13_random(query, 2)) return -1;
    query[2] = 1; query[5] = 1;
    size_t p = 12, name_len = strlen(origin), at = 0;
    for (size_t i = 0; i < name_len; i++) {
        unsigned c = (unsigned char)origin[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        expected[i] = (char)c;
    }
    expected[name_len] = 0;
    while (at < name_len) {
        size_t end = at;
        while (end < name_len && expected[end] != '.') end++;
        size_t l = end - at;
        if (!l || l > 63 || p + l + 1 >= sizeof query) return -1;
        for (size_t i = at; i < end; i++) {
            unsigned c = (unsigned char)expected[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return -1;
        }
        query[p++] = (uint8_t)l; memcpy(query + p, expected + at, l); p += l;
        at = end + 1;
    }
    query[p++] = 0; query[p++] = 0; query[p++] = 65; query[p++] = 0; query[p++] = 1;
    char resolver[64] = "127.0.0.1", line[256], parsed[64];
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (f) {
        while (fgets(line, sizeof line, f)) {
            if (sscanf(line, "nameserver %63s", parsed) == 1) {
                snprintf(resolver, sizeof resolver, "%s", parsed); break;
            }
        }
        fclose(f);
    }
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;
    int af; socklen_t sl;
    if (inet_pton(AF_INET, resolver, &v4->sin_addr) == 1) {
        af = AF_INET; sl = sizeof *v4; v4->sin_family = AF_INET; v4->sin_port = htons(53);
    } else if (inet_pton(AF_INET6, resolver, &v6->sin6_addr) == 1) {
        af = AF_INET6; sl = sizeof *v6; v6->sin6_family = AF_INET6; v6->sin6_port = htons(53);
    } else return -1;
    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
#ifdef SO_MARK
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark)) { close(fd); return -1; }
#else
    (void)mark;
#endif
    if (connect(fd, (struct sockaddr *)&ss, sl) || send(fd, query, p, 0) != (ssize_t)p) {
        close(fd); return -1;
    }
    struct pollfd pf = {fd, POLLIN, 0};
    int ready = poll(&pf, 1, 1500);
    ssize_t received = ready > 0 ? recv(fd, reply, sizeof reply, 0) : -1;
    close(fd);
    if (received < 12) return -1;
    size_t n = (size_t)received;
    if (memcmp(query, reply, 2) || !(reply[2] & 0x80) ||
        (reply[2] & 0x7a) || (reply[3] & 15) || dns16(reply + 4) != 1) return -1;
    p = 12; char owner[256];
    if (ech_dns_name(reply, n, &p, owner) || strcmp(owner, expected) ||
        p + 4 > n || dns16(reply + p) != 65 || dns16(reply + p + 2) != 1) return -1;
    p += 4;
    unsigned count = dns16(reply + 6);
    if (count > 64) return -1;
    for (unsigned i = 0; i < count; i++) {
        if (ech_dns_name(reply, n, &p, owner) || p + 10 > n) return -1;
        unsigned type = dns16(reply + p), cls = dns16(reply + p + 2);
        size_t end = p + 10 + dns16(reply + p + 8); p += 10;
        if (end > n) return -1;
        if (type != 65 || cls != 1 || strcmp(owner, expected)) { p = end; continue; }
        if (end - p < 3 || !dns16(reply + p)) { p = end; continue; }
        p += 2; char target[256];
        if (ech_dns_name(reply, n, &p, target) || p > end) return -1;
        if (target[0] && strcmp(target, expected)) { p = end; continue; }
        int last = -1, found = 0, compatible = 1;
        d2k_ech_config candidate;
        while (p < end) {
            if (end - p < 4) return -1;
            unsigned key = dns16(reply + p); size_t l = dns16(reply + p + 2); p += 4;
            if ((int)key <= last || l > end - p) return -1;
            last = (int)key;
            if (key == 3 && (l != 2 || dns16(reply + p) != 443)) compatible = 0;
            if (key == 5 && !d2k_ech_config_parse(reply + p, l, &candidate)) found = 1;
            p += l;
        }
        if (found && compatible) { *config = candidate; return 0; }
    }
    return -1;
}

/* RFC 9112 §4, RFC 9110 §15.2. Записи TLS не являются границами HTTP.
   Нужны окончательные заголовки И полное тело по framing: один HTTP 200 не
   означает, что страница загрузилась (на RuTracker тело обрывалось около
   24 КБ при уже полученных заголовках). Происхождение страницы и цепочка
   сертификата здесь всё ещё не проверяются. */
/* Ищет CRLFCRLF в ПАМЯТИ, а не строковыми функциями: ответ содержит нулевые
   байты, и strstr останавливается на первом из них. */
static const uint8_t *find_hdr_end(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 3 < n; i++) {
        if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) {
            return b + i;
        }
    }
    return NULL;
}

/* Конец ПЕРВОЙ строки (CRLF) в памяти, либо NULL. */
static const uint8_t *find_eol(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 1 < n; i++) {
        if (b[i] == 13 && b[i + 1] == 10) { return b + i; }
    }
    return NULL;
}

static uint8_t lower_ascii(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

static int span_eq_ascii_ci(const uint8_t *p, size_t n, const char *s) {
    size_t m = strlen(s);
    if (n != m) { return 0; }
    for (size_t i = 0; i < n; i++) {
        if (lower_ascii(p[i]) != (uint8_t)s[i]) { return 0; }
    }
    return 1;
}

/* Cloudflare marks every challenge page with this response header. Checking
   the exact marker is safer than treating every HTTP error as a blocked page:
   some legitimate endpoints return 404/403 while still proving that the
   request reached the intended application. */
static int has_cf_challenge(const uint8_t *buf, size_t hdr_len,
                           const uint8_t *status_eol) {
    size_t pos = (size_t)(status_eol - buf) + 2;
    while (pos < hdr_len) {
        const uint8_t *line = buf + pos;
        const uint8_t *eol = find_eol(line, hdr_len - pos);
        size_t line_len = eol ? (size_t)(eol - line) : hdr_len - pos;
        const uint8_t *colon = memchr(line, ':', line_len);
        if (colon && span_eq_ascii_ci(line, (size_t)(colon - line), "cf-mitigated")) {
            size_t off = (size_t)(colon - line) + 1;
            size_t end = line_len;
            while (off < end && (line[off] == ' ' || line[off] == '\t')) { off++; }
            while (end > off && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
            if (span_eq_ascii_ci(line + off, end - off, "challenge")) { return 1; }
        }
        if (!eol) { break; }
        pos += line_len + 2;
    }
    return 0;
}

/* Код окончательного ответа HTTP (тело и framing возвращаются отдельно),
 * либо 0 — «полных заголовков нет».
 *
 * НОЛЬ В ТЕЛЕ БОЛЬШЕ НИЧЕГО НЕ РЕШАЕТ. Здесь стояло `if (memchr(...0...)) break;`
 * — разбор бросался, едва во ВХОДЯЩИХ байтах попадался нулевой. Тело ответа
 * его содержит сплошь и рядом, и зонд выбрасывал полноценный ответ вместе с
 * кандидатом, который его добыл.
 *
 * Замерено на живой линии 14.09.2026: i.ytimg.com отдаёт
 * «HTTP/1.1 404 Not Found» в первом же чтении (1378 байт, конец заголовков на
 * месте), нулевой байт лежит на смещении 386 — в ТЕЛЕ. Клиент в ту же секунду
 * получал 404 за 0,16 с, а зонд докладывал «нет полных заголовков
 * окончательного HTTP-ответа» и объявлял рабочий план негодным. Так за ночь
 * терялись найденные обходы (0010, R2: ложный ответ о свойствах DPI).
 *
 * Заголовки HTTP нулевого байта содержать не вправе, поэтому проверка на него
 * осталась — но только ДО конца заголовков, где она и означает «ответ битый».
 */
/* Чтение прикладных данных отдано вызывающему функцией: разбор ответа один и
   тот же, а сессия под ним бывает и 1.3, и 1.2 (d2k_tls12.h — зачем второй
   клиент). Второй экземпляр этого разбора рядом означал бы, что находка
   14.09 про нулевой байт в теле живёт в одном из них и не живёт в другом. */
typedef long (*read_fn)(void *sess, uint8_t *buf, size_t cap, int wait_ms,
                        char *err, size_t errcap);

static long read13(void *sess, uint8_t *buf, size_t cap, int wait_ms,
                   char *err, size_t errcap) {
    return d2k_tls_read((d2k_tls *)sess, buf, cap, wait_ms, err, errcap);
}

static long read12(void *sess, uint8_t *buf, size_t cap, int wait_ms,
                   char *err, size_t errcap) {
    return d2k_tls12_read((d2k_tls12 *)sess, buf, cap, wait_ms, err, errcap);
}

typedef struct {
    read_fn rd;
    void *sess;
    uint8_t *buf;
    size_t used, pos;
    int64_t until;
    char *err;
    size_t errcap;
    d2k_resource_scan *scan;
    uint8_t prefix[4096];
    size_t prefix_len;
} body_stream;

static void body_feed(body_stream *s, const uint8_t *p, size_t n) {
    size_t take = sizeof s->prefix - s->prefix_len;
    if (take > n) take = n;
    memcpy(s->prefix + s->prefix_len, p, take);
    s->prefix_len += take;
    d2k_resource_feed(s->scan, p, n);
}

/* Следующий байт из уже прочитанной части ответа либо из TLS. */
static int body_byte(body_stream *s, uint8_t *out) {
    if (s->pos == s->used) {
        int64_t left = s->until - verify_now_ms();
        if (left <= 0) { snprintf(s->err, s->errcap, "тайм-аут чтения тела"); return -1; }
        long n = s->rd(s->sess, s->buf, 8192, (int)left, s->err, s->errcap);
        if (n <= 0) { return (int)n; }
        s->used = (size_t)n;
        s->pos = 0;
    }
    *out = s->buf[s->pos++];
    return 1;
}

static int body_exact(body_stream *s, uint64_t n, uint64_t *bytes) {
    while (n) {
        if (s->pos == s->used) {
            int64_t left = s->until - verify_now_ms();
            if (left <= 0) { snprintf(s->err, s->errcap, "тайм-аут чтения тела"); return -1; }
            long got = s->rd(s->sess, s->buf, 8192, (int)left, s->err, s->errcap);
            if (got <= 0) { return -1; }
            s->used = (size_t)got;
            s->pos = 0;
        }
        size_t take = s->used - s->pos;
        if ((uint64_t)take > n) { take = (size_t)n; }
        body_feed(s, s->buf + s->pos, take);
        s->pos += take;
        n -= take;
        *bytes += take;
    }
    return 0;
}

static int body_line(body_stream *s, char *line, size_t cap) {
    size_t n = 0;
    int cr = 0;
    for (;;) {
        uint8_t c;
        int r = body_byte(s, &c);
        if (r <= 0) { return -1; }
        if (cr) {
            if (c != '\n') { return -1; }
            line[n] = '\0';
            return 0;
        }
        if (c == '\r') { cr = 1; continue; }
        if (c == '\n' || n + 1 >= cap) { return -1; }
        line[n++] = (char)c;
    }
}

/* Читает тело целиком по Content-Length, chunked или закрытию TLS. Для
   chunked тело и framing считаются раздельно; размер чанка проверяется до
   сложения, а завершение требует нулевого чанка и конца trailers. */
static int read_http_body(body_stream *s, int status, int has_length,
                          uint64_t length, int chunked,
                          uint64_t *body_bytes, uint64_t *body_expected) {
    *body_bytes = 0;
    *body_expected = has_length ? length : 0;
    if (status == 204 || status == 304) { return 1; }
    if (has_length) {
        uint64_t already = (uint64_t)(s->used - s->pos);
        if (already > length) { already = length; }
        body_feed(s, s->buf + s->pos, (size_t)already);
        s->pos += (size_t)already;
        *body_bytes = already;
        if (already < length && body_exact(s, length - already, body_bytes) != 0) { return 0; }
        return 1;
    }
    if (chunked) {
        char line[128];
        for (;;) {
            if (body_line(s, line, sizeof line) != 0) { return 0; }
            uint64_t chunk = 0;
            size_t i = 0, digits = 0;
            while (line[i] && line[i] != ';') {
                unsigned char c = (unsigned char)line[i++];
                unsigned v;
                if (c >= '0' && c <= '9') { v = c - '0'; }
                else if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; }
                else if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; }
                else { return 0; }
                if (chunk > (UINT64_MAX - v) / 16) { return 0; }
                chunk = chunk * 16 + v;
                digits++;
            }
            if (!digits || UINT64_MAX - *body_bytes < chunk) { return 0; }
            if (chunk == 0) {
                do {
                    if (body_line(s, line, sizeof line) != 0) { return 0; }
                } while (line[0]);
                *body_expected = *body_bytes;
                return 1;
            }
            if (body_exact(s, chunk, body_bytes) != 0) { return 0; }
            uint8_t a, b;
            if (body_byte(s, &a) != 1 || body_byte(s, &b) != 1 || a != '\r' || b != '\n') {
                return 0;
            }
        }
    }
    /* Без явного framing RFC 9112 использует закрытие соединения как конец
       тела. Читаем до close_notify; timeout/RST — неполная страница. */
    *body_bytes = (uint64_t)(s->used - s->pos);
    body_feed(s, s->buf + s->pos, s->used - s->pos);
    s->pos = s->used;
    for (;;) {
        int64_t left = s->until - verify_now_ms();
        if (left <= 0) { snprintf(s->err, s->errcap, "тайм-аут чтения тела"); return 0; }
        long got = s->rd(s->sess, s->buf, 8192, (int)left, s->err, s->errcap);
        if (got == 0) { *body_expected = *body_bytes; return 1; }
        if (got < 0) { return 0; }
        if (UINT64_MAX - *body_bytes < (uint64_t)got) { return 0; }
        body_feed(s, s->buf, (size_t)got);
        *body_bytes += (uint64_t)got;
    }
}

static int read_status_rd(read_fn rd, void *sess, int wait_ms,
                          int *cloudflare_challenge, uint64_t *body_bytes,
                          uint64_t *body_expected, int *body_complete,
                          int *body_has_length, int *body_chunked,
                          int *body_framing_valid, int *body_encoding,
                          char *location, size_t location_cap,
                          d2k_resource *resources, size_t *n_resources,
                          d2k_http_reply_result *http_reply,
                          char *err, size_t errcap) {
    uint8_t buf[8193];
    size_t used = 0;
    *http_reply = (d2k_http_reply_result){D2K_HTTP_NEUTRAL, ""};
    if (n_resources) *n_resources = 0;
    if (cloudflare_challenge) { *cloudflare_challenge = 0; }
    if (body_bytes) { *body_bytes = 0; }
    if (body_expected) { *body_expected = 0; }
    if (body_complete) { *body_complete = 0; }
    if (body_has_length) { *body_has_length = 0; }
    if (body_chunked) { *body_chunked = 0; }
    if (body_framing_valid) { *body_framing_valid = 0; }
    if (body_encoding) { *body_encoding = 0; }
    if (location && location_cap) { location[0] = '\0'; }
    int64_t until = verify_now_ms() + (wait_ms > 0 ? wait_ms : 8000);
    for (;;) {
        const uint8_t *end = find_hdr_end(buf, used);
        if (end) {
            size_t hdr_len = (size_t)(end - buf);
            /* Ноль ВНУТРИ заголовков — ответ битый, а не «ещё не всё». */
            if (memchr(buf, 0, hdr_len)) { return 0; }
            /* With no header fields, the status line's CRLF is the first
             * half of CRLFCRLF. Include it in the line search, but keep
             * the body excluded from the header/NUL validation above. */
            const uint8_t *eol = find_eol(buf, hdr_len + 2);
            if (!eol) { return 0; }
            size_t line_len = (size_t)(eol - buf);
            if (line_len < 13 || memcmp(buf, "HTTP/1.", 7) != 0 ||
                (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ' ||
                buf[9] < '1' || buf[9] > '5' || buf[10] < '0' || buf[10] > '9' ||
                buf[11] < '0' || buf[11] > '9' || buf[12] != ' ') {
                return 0;
            }
            for (size_t p = 13; p < line_len; p++) {
                if ((buf[p] < 32 && buf[p] != '\t') || buf[p] == 127) { return 0; }
            }
            int code = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + buf[11] - '0';
            if (code >= 200) {
                /* Legal denial is established by valid final headers/status,
                   independently of malformed body framing below. */
                if (code == 451)
                    *http_reply = d2k_http_reply_classify(code, NULL, 0, NULL, 0, 0);
                if (cloudflare_challenge) {
                    *cloudflare_challenge = has_cf_challenge(buf, hdr_len, eol);
                }
                int has_length = 0, chunked = 0, framing_valid = 1;
                int transfer_encoding_seen = 0;
                int encoding = 0;
                int encoding_seen = 0;
                int location_seen = 0;
                int html = 0;
                uint64_t length = 0;
                size_t pos = (size_t)(eol - buf) + 2;
                while (pos < hdr_len) {
                    const uint8_t *line = buf + pos;
                    const uint8_t *le = find_eol(line, hdr_len - pos);
                    size_t ln = le ? (size_t)(le - line) : hdr_len - pos;
                    const uint8_t *colon = memchr(line, ':', ln);
                    if (colon) {
                        size_t kn = (size_t)(colon - line), v = kn + 1;
                        while (v < ln && (line[v] == ' ' || line[v] == '\t')) { v++; }
                        if (span_eq_ascii_ci(line, kn, "content-type")) {
                            size_t end = v;
                            while (end < ln && line[end] != ';' && line[end] != ' ') end++;
                            html = span_eq_ascii_ci(line + v, end - v, "text/html");
                        } else if (span_eq_ascii_ci(line, kn, "content-length")) {
                            uint64_t x = 0; size_t digits = 0;
                            while (v < ln && line[v] >= '0' && line[v] <= '9') {
                                unsigned d = (unsigned)(line[v++] - '0');
                                if (x > (UINT64_MAX - d) / 10) { return code; }
                                x = x * 10 + d; digits++;
                            }
                            while (v < ln && (line[v] == ' ' || line[v] == '\t')) { v++; }
                            if (!digits || v != ln || (has_length && x != length)) { return code; }
                            has_length = 1; length = x;
                        } else if (span_eq_ascii_ci(line, kn, "transfer-encoding")) {
                            size_t end = ln;
                            while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
                            if (transfer_encoding_seen++ ||
                                !span_eq_ascii_ci(line + v, end - v, "chunked")) {
                                framing_valid = 0;
                            } else { chunked = 1; }
                        } else if (span_eq_ascii_ci(line, kn, "content-encoding")) {
                            size_t end = ln;
                            while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
                            /* Multiple Content-Encoding fields are a coding
                               stack, not interchangeable aliases. This small
                               verifier does not decode stacks; keep them
                               explicitly unknown so the volume matcher cannot
                               confuse them with a plain or one-layer gzip body. */
                            if (encoding_seen++) { encoding = 2; }
                            else if (span_eq_ascii_ci(line + v, end - v, "gzip")) { encoding = 1; }
                            else if (span_eq_ascii_ci(line + v, end - v, "identity")) { encoding = 0; }
                            else { encoding = 2; }
                        } else if (span_eq_ascii_ci(line, kn, "location") && location && location_cap) {
                            int duplicate = location_seen++;
                            if (duplicate) framing_valid = 0;
                            size_t end = ln;
                            while (end > v && (line[end - 1] == ' ' || line[end - 1] == '\t')) { end--; }
                            size_t value_len = end - v;
                            if (!duplicate && value_len < location_cap) {
                                int safe = 1;
                                for (size_t k = v; k < end; k++) {
                                    if (line[k] < 0x21 || line[k] == 0x7f) { safe = 0; break; }
                                }
                                if (safe) {
                                    memcpy(location, line + v, value_len);
                                    location[value_len] = '\0';
                                }
                            }
                        }
                    }
                    if (!le) { break; }
                    pos += ln + 2;
                }
                body_stream bs;
                memset(&bs, 0, sizeof bs);
                bs.rd = rd; bs.sess = sess; bs.buf = buf;
                bs.used = used; bs.pos = hdr_len + 4;
                bs.until = until; bs.err = err; bs.errcap = errcap;
                d2k_resource_scan scan = {0};
                if (html && encoding == 0 && code >= 200 && code < 300 &&
                    (!cloudflare_challenge || !*cloudflare_challenge)) bs.scan = &scan;
                uint64_t got = 0, expected = 0;
                /* Ambiguous framing must never be accepted as a complete
                   response: intermediaries disagree about TE vs CL and can
                   otherwise make a truncated body look whole. */
                int complete = framing_valid && !(has_length && chunked) &&
                    read_http_body(&bs, code, has_length, length,
                                   chunked, &got, &expected);
                if (body_bytes) { *body_bytes = got; }
                if (body_expected) { *body_expected = expected; }
                if (body_complete) { *body_complete = complete; }
                if (body_has_length) { *body_has_length = has_length; }
                if (body_chunked) { *body_chunked = chunked; }
                if (body_framing_valid) {
                    *body_framing_valid = framing_valid && !(has_length && chunked);
                }
                if (body_encoding) { *body_encoding = encoding; }
                *http_reply = d2k_http_reply_classify(code, location, encoding,
                    bs.prefix, bs.prefix_len, got + (complete ? 0 : 1));
                if (complete && bs.scan && resources && n_resources) {
                    memcpy(resources, scan.refs, sizeof scan.refs);
                    *n_resources = scan.count;
                }
                return code;
            }
            if (code == 101) { return 0; } /* upgrade не запрашивали */
            /* Промежуточный ответ (1xx) — отбрасываем его вместе с
               заголовками и ждём окончательного. */
            size_t consumed = hdr_len + 4;
            memmove(buf, buf + consumed, used - consumed);
            used -= consumed;
            continue;
        }
        if (used >= sizeof buf - 1) { return 0; }
        int64_t left = until - verify_now_ms();
        if (left <= 0) { return 0; }
        long got = rd(sess, buf + used, sizeof buf - 1 - used, (int)left, err, errcap);
        if (got <= 0) { return 0; }
        used += (size_t)got;
    }
}

d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms, size_t hello_wire) {
    return d2k_verify_probe_on(-1, ip, port, sni, deadline_ms, hello_wire);
}

/* use_fd — УЖЕ ЗАНЯТЫЙ сокет (d2k_props_bind), чей местный порт вызывающий
   назвал датапату заранее, чтобы пробный план достался только этому потоку.
   Меньше нуля — создать свой, тогда это в точности d2k_verify_probe. */
typedef int (*write_fn)(void *sess, const uint8_t *buf, size_t len,
                        char *err, size_t errcap);

static int write13(void *sess, const uint8_t *buf, size_t len,
                   char *err, size_t errcap) {
    return d2k_tls_write((d2k_tls *)sess, buf, len, err, errcap);
}

static int write12(void *sess, const uint8_t *buf, size_t len,
                   char *err, size_t errcap) {
    return d2k_tls12_write((d2k_tls12 *)sess, buf, len, err, errcap);
}

/* Resolve only same-origin HTTPS redirects. A redirect to a different host
   starts a different measurement target and must not be credited to this one. */
static int redirect_path(const char *location, const char *host,
                         char *path, size_t path_cap) {
    if (!location || !location[0] || !host || !host[0] || !path || path_cap < 2) { return 0; }
    const char *p = location;
    if (strlen(p) >= 8 && span_eq_ascii_ci((const uint8_t *)p, 8, "https://")) {
        p += 8;
        const char *authority = p;
        while (*p && *p != '/' && *p != '?' && *p != '#') { p++; }
        size_t authority_len = (size_t)(p - authority);
        size_t host_len = strlen(host);
        int same = authority_len == host_len &&
                   span_eq_ascii_ci((const uint8_t *)authority, authority_len, host);
        if (!same && authority_len == host_len + 4 &&
            span_eq_ascii_ci((const uint8_t *)authority, host_len, host) &&
            memcmp(authority + host_len, ":443", 4) == 0) { same = 1; }
        if (!same) { return 0; }
        if (*p == '?') {
            if (path_cap < strlen(p) + 2) { return 0; }
            path[0] = '/'; strcpy(path + 1, p);
            return 1;
        }
        if (*p != '/') { p = "/"; }
    } else if (*p != '/') {
        return 0;
    }
    size_t n = strlen(p);
    if (n == 0 || n >= path_cap || p[0] != '/') { return 0; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c <= 0x20 || c == 0x7f || c == '#') { return 0; }
    }
    memcpy(path, p, n + 1);
    return 1;
}

/* A complete redirect is an application response from the measured host,
   not proof that its destination loaded. Never follow a different origin. */
static int https_redirect_response(int code, const char *location) {
    if (code != 301 && code != 302 && code != 303 && code != 307 && code != 308) return 0;
    if (!location || strlen(location) < 9 ||
        !span_eq_ascii_ci((const uint8_t *)location, 8, "https://")) return 0;
    const char *p = location + 8;
    int host_chars = 0;
    for (; *p && *p != '/' && *p != '?' && *p != '#'; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) host_chars++;
        else if (c != '.' && c != '-' && c != ':' && c != '[' && c != ']') return 0;
    }
    if (!host_chars) return 0;
    for (; *p; p++) if ((unsigned char)*p <= 0x20 || (unsigned char)*p == 0x7f) return 0;
    return 1;
}

static void request_complete_page(read_fn rd, write_fn wr, void *sess,
                                  const char *host, int encoding,
                                  const char *initial_path,
                                  int deadline_ms, int tls12,
                                  d2k_ver_result *r, char *err, size_t errcap) {
    char path[1024] = "/";
    if (initial_path) snprintf(path, sizeof path, "%s", initial_path);
    const char *accept_encoding = encoding == 1 ? "gzip" :
                                  encoding == 2 ? "gzip, deflate" : "identity";
    for (int redirects = 0; redirects <= 3; redirects++) {
        char req[2048];
        int n = snprintf(req, sizeof req,
                         "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                         "Accept: */*\r\nAccept-Encoding: %s\r\nConnection: keep-alive\r\n\r\n",
                         path, host, accept_encoding);
        if (n <= 0 || (size_t)n >= sizeof req) {
            snprintf(r->reason, sizeof r->reason, "запрос не собрался: путь/имя слишком длинные");
            return;
        }
        if (wr(sess, (const uint8_t *)req, (size_t)n, err, errcap) != 0) {
            snprintf(r->reason, sizeof r->reason, "запрос не ушёл: %.150s", err);
            return;
        }
        r->location[0] = '\0';
        d2k_http_reply_result http_reply;
        int code = read_status_rd(rd, sess, deadline_ms,
                                  &r->cloudflare_challenge, &r->body_bytes,
                                  &r->body_expected, &r->body_complete,
                                  &r->body_has_length, &r->body_chunked,
                                  &r->body_framing_valid, &r->body_encoding, r->location,
                                  sizeof r->location, r->resources, &r->n_resources,
                                  &http_reply, err, errcap);
        r->status = code;
        r->http_outcome = http_reply.outcome;
        snprintf(r->http_evidence, sizeof r->http_evidence, "%s", http_reply.evidence);
        if (r->cloudflare_challenge) { r->level = D2K_VER_CHALLENGE; return; }
        if (http_reply.outcome == D2K_HTTP_BLOCKED ||
            http_reply.outcome == D2K_HTTP_LEGAL_DENIAL) {
            r->level = http_reply.outcome == D2K_HTTP_BLOCKED ?
                D2K_VER_BLOCKPAGE : D2K_VER_DENIED;
            snprintf(r->reason, sizeof r->reason, "HTTP отказ: %s", http_reply.evidence);
            return;
        }
        if (code >= 300 && code < 400) {
            char next[sizeof path];
            if (r->body_framing_valid && redirects < 3 &&
                redirect_path(r->location, host, next, sizeof next)) {
                if (initial_path && !d2k_resource_path_ok(next)) {
                    r->level = D2K_VER_HANDSHAKE;
                    snprintf(r->reason, sizeof r->reason, "stylesheet перенаправлен не на ресурс; не подтверждено");
                    return;
                }
                memcpy(path, next, strlen(next) + 1);
                continue;
            }
            if (!initial_path && r->body_complete &&
                https_redirect_response(code, r->location) &&
                !redirect_path(r->location, host, next, sizeof next)) {
                r->level = D2K_VER_APPLICATION;
                snprintf(r->reason, sizeof r->reason,
                         "HTTP %d, HTTPS redirect получен полностью (%llu байт); цель перехода не проверялась",
                         code, (unsigned long long)r->body_bytes);
                return;
            }
            r->level = D2K_VER_HANDSHAKE;
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d redirect не является подтверждением страницы этой цели", code);
            return;
        }
        if (code && r->body_complete) {
            r->level = D2K_VER_APPLICATION;
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d, тело загружено полностью (%llu байт)%s", code,
                     (unsigned long long)r->body_bytes, tls12 ? " по TLS 1.2" : "");
        } else if (code) {
            snprintf(r->reason, sizeof r->reason,
                     "HTTP %d, тело оборвалось (%llu/%llu байт): %.80s", code,
                     (unsigned long long)r->body_bytes,
                     (unsigned long long)r->body_expected, err);
        } else {
            snprintf(r->reason, sizeof r->reason,
                     "нет полных заголовков окончательного HTTP-ответа: %.100s", err);
        }
        return;
    }
    r->level = D2K_VER_HANDSHAKE;
    snprintf(r->reason, sizeof r->reason, "превышена глубина same-origin redirect");
}

/* Set the measurement mark before connect(). SO_MARK applied to a connected
   socket can leave the route selected without that mark, so baseline probes
   must prepare the socket first and pass its already-bound fd to the shared
   connection helper. */
static int verify_contact(int use_fd, const char *ip, uint16_t port,
                          uint32_t mark, uint8_t family, uint8_t *local_addr,
                          uint16_t *local_port, int *out_fd) {
    int fd = use_fd;
    if (mark) {
        if (fd < 0 && d2k_props_bind_family(family, &fd, NULL) != 0) { return -1; }
        if (d2k_mark_hook(fd, mark) != 0) {
            close(fd);
            return -2;
        }
    }
    return d2k_props_contact_on_family(fd, ip, port, (d2k_hello){ NULL, 0 }, family,
                                local_addr, local_port, out_fd);
}

static d2k_ver_result verify_probe13_internal(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire, int encoding, uint32_t mark,
                                        const char *path, const d2k_ech_config *ech) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;   /* не смотрели — «сказать нечего», а не «нет» (§2.4) */
    if (path && !d2k_resource_path_ok(path)) {
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "недопустимый путь stylesheet-пробы");
        return r;
    }
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени HTTP");
            return r;
        }
    }

    /* Байты приветствия сюда НЕ передаются: рукопожатие ведёт d2k_tls13,
       своим ключом, и чужой ClientHello перед ним был бы мусором в начале
       потока. Пустое приветствие d2k_props_contact принимает намеренно —
       нужны от неё ровно непомеченный сокет, открытый наружу, и местные
       адрес с портом. */
    r.family = ip && strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, mark, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        snprintf(r.reason, sizeof r.reason, contact == -2
                 ? "метка измерительного сокета не поставилась" : "нет TCP");
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");

    char err[160];
    err[0] = '\0';
    d2k_tls *t = NULL;
    int tls_rc = ech ? d2k_tls_connect_ech(r.fd, sni, ech, deadline_ms,
                                          hello_wire, &t, err, sizeof err)
                     : d2k_tls_connect(r.fd, sni, deadline_ms, hello_wire, &t, err, sizeof err);
    if (tls_rc != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS: %.150s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_tls_peer_name(t);
    r.ech_accepted = d2k_tls_ech_accepted(t);
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    request_complete_page(read13, write13, t, host, encoding, path,
                          deadline_ms, 0, &r, err, sizeof err);
    /* Сессию освобождаем, сокет — нет: d2k_tls_free владения им не берёт
       (d2k_tls13.h), а закрыть его здесь значило бы послать FIN и потерять
       ячейку потока в датапате раньше, чем вызывающий свяжет с ней событие. */
    d2k_tls_free(t);
    return r;
}

static d2k_ver_result verify_probe13_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int encoding,
    uint32_t mark, const char *path) {
    return verify_probe13_internal(use_fd, ip, port, sni, deadline_ms,
                                   hello_wire, encoding, mark, path, NULL);
}

static void ech_http_denial(d2k_ver_result *r) {
    if (r->status >= 400 && r->level != D2K_VER_DENIED && r->level != D2K_VER_BLOCKPAGE) {
        /* An origin refusal/rate limit is not permission to hammer it. */
        r->level = D2K_VER_CHALLENGE;
        snprintf(r->reason, sizeof r->reason, "ECH origin ответил HTTP %d; подбор не должен усиливать отказ сервера", r->status);
    }
}

d2k_ver_result d2k_verify_probe_ech_on(int use_fd, const char *ip, uint16_t port,
    const char *origin, const d2k_ech_config *config, int deadline_ms,
    size_t hello_wire, uint32_t mark, const char *path) {
    if (!config || !origin || !origin[0]) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r); r.fd = -1; r.name_ok = -1;
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "нет ECH-конфигурации/origin; опыт не состоялся");
        return r;
    }
    d2k_ver_result r = verify_probe13_internal(use_fd, ip, port, origin, deadline_ms,
                                               hello_wire, 0, mark, path, config);
    ech_http_denial(&r);
    return r;
}

d2k_ver_result d2k_verify_probe_ech_origin_on(int use_fd, const char *ip,
    uint16_t port, const char *outer_name, const char *origin, int deadline_ms,
    size_t hello_wire, uint32_t dns_mark, const char *path) {
    d2k_ech_config config;
    if (!outer_name || !origin || d2k_ech_resolve(origin, dns_mark, &config) ||
        strcmp(outer_name, config.public_name)) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r); r.fd = -1; r.name_ok = -1;
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "ECH witness/config не совпали; опыт не состоялся");
        return r;
    }
    return d2k_verify_probe_ech_on(use_fd, ip, port, origin, &config, deadline_ms,
                                  hello_wire, use_fd < 0 ? dns_mark : 0, path);
}

d2k_ver_result d2k_verify_probe_on(int use_fd, const char *ip, uint16_t port,
                                   const char *sni, int deadline_ms,
                                   size_t hello_wire) {
    return verify_probe13_on(use_fd, ip, port, sni, deadline_ms, hello_wire, 2, 0, NULL);
}

/* ФОРМА КЛИЕНТА — И КРИТЕРИЙ ОРИГИНАЛА (задача 37, F3; D2K_SPEC §4, §7).
   Классификатор шлёт снимок клиента байт в байт и засчитывает ServerHello
   (trigger.go); зонд подтверждения прежде всегда предлагал http/1.1 и ждал
   HTTP-ответа. Для MQTT поверх TLS (edge-mqtt-fallback, поле 02.10.2026)
   сервер отвечал тревогой 120 на каждое испытание, то есть «приветствие
   прошло коробку, а зонд спросил не тот протокол». Здесь зонд предлагает
   ALPN клиента и останавливается на завершённом рукопожатии: свой
   прикладной обмен на чужом протоколе мы не ведём и его не выдумываем. */
d2k_ver_result d2k_verify_probe_alpn_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms, size_t hello_wire,
                                        const uint8_t *alpn_list, size_t alpn_len) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    if ((alpn_len && !alpn_list) || alpn_len > 256 || !ip || !ip[0]) {
        if (use_fd >= 0) close(use_fd);
        return r;
    }
    r.family = strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, 0, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TCP");
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");
    char err[160];
    err[0] = '\0';
    d2k_tls *t = NULL;
    if (d2k_tls_connect_alpn(r.fd, sni, deadline_ms, hello_wire, alpn_list, alpn_len,
                             &t, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS (ALPN клиента): %.140s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.handshake_proof = 1;
    r.name_ok = d2k_tls_peer_name(t);
    snprintf(r.reason, sizeof r.reason,
             "рукопожатие TLS с ALPN клиента завершено; протокол клиента не HTTP — "
             "прикладной уровень не измерен");
    d2k_tls_free(t);
    return r;
}

/* ТО ЖЕ САМОЕ, НО ПО TLS 1.2 — и это не «вторая проба», а та же проба другим
   протоколом. Зовётся там, где КЛИЕНТ старой формы: подтверждать его обход
   современным рукопожатием значит записывать план под форму, которой у него
   нет, и он такого плана не получит вовсе (MVP_CHECKLIST, пункт 3).

   Приветствие зонд собирает сам и добивает до длины клиентского — ровно как
   зонд 1.3 и по той же причине. Почему не профиль старого клиента, сказано в
   шапке d2k_tls12.h: он предлагает шифрнаборы, которых зонд не умеет, и
   сервер выбирал бы именно их. */
static d2k_ver_result verify_probe12_internal(int use_fd, const char *ip, uint16_t port,
                                             const char *sni, int deadline_ms,
                                             size_t hello_wire, int encoding,
                                             uint32_t mark, const char *path) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    if (path && !d2k_resource_path_ok(path)) {
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "недопустимый путь stylesheet-пробы");
        return r;
    }
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени HTTP");
            return r;
        }
    }

    r.family = ip && strchr(ip, ':') ? 6 : 4;
    int contact = verify_contact(use_fd, ip, port, mark, r.family,
                                 r.local_addr, &r.local_port, &r.fd);
    if (contact != 0) {
        snprintf(r.reason, sizeof r.reason, contact == -2
                 ? "метка измерительного сокета не поставилась" : "нет TCP");
        return r;
    }
    r.level = D2K_VER_TRANSPORT;
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    snprintf(r.reason, sizeof r.reason, "транспорт встал, рукопожатия нет");

    char err[160];
    err[0] = '\0';
    d2k_tls12 *t = NULL;
    if (d2k_tls12_connect(r.fd, sni, deadline_ms, hello_wire, &t, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "нет TLS 1.2: %.140s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_tls12_peer_name(t);
    snprintf(r.reason, sizeof r.reason, "рукопожатие 1.2 завершено, приложение молчит");

    request_complete_page(read12, write12, t, host, encoding, path,
                          deadline_ms, 1, &r, err, sizeof err);
    d2k_tls12_free(t);
    return r;
}

d2k_ver_result d2k_verify_probe12_on(int use_fd, const char *ip, uint16_t port,
                                     const char *sni, int deadline_ms,
                                     size_t hello_wire) {
    return verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                   hello_wire, 2, 0, NULL);
}

d2k_ver_result d2k_verify_probe_identity_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12) {
    if (tls12) return verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                             hello_wire, 0, 0, NULL);
    return verify_probe13_on(use_fd, ip, port, sni, deadline_ms, hello_wire, 0, 0, NULL);
}

d2k_ver_result d2k_verify_probe_gzip_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12) {
    if (tls12) return verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                             hello_wire, 1, 0, NULL);
    return verify_probe13_on(use_fd, ip, port, sni, deadline_ms, hello_wire, 1, 0, NULL);
}

d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
                                         const char *sni, int deadline_ms,
                                         size_t hello_wire, int tls12,
                                         int encoding, uint32_t mark) {
    if (encoding != 0 && encoding != 1) {
        d2k_ver_result r;
        memset(&r, 0, sizeof r);
        r.fd = -1;
        r.name_ok = -1;
        snprintf(r.reason, sizeof r.reason, "неподдерживаемый режим сжатия");
        return r;
    }
    if (tls12) {
        return verify_probe12_internal(-1, ip, port, sni, deadline_ms,
                                       hello_wire, encoding, mark, NULL);
    }
    return verify_probe13_on(-1, ip, port, sni, deadline_ms,
                             hello_wire, encoding, mark, NULL);
}

d2k_ver_result d2k_verify_probe_path_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12,
    int encoding, uint32_t mark, const char *path) {
    if (encoding < 0 || encoding > 2) {
        d2k_ver_result r = {0}; r.fd = -1; r.name_ok = -1;
        if (use_fd >= 0) close(use_fd);
        snprintf(r.reason, sizeof r.reason, "неподдерживаемое сжатие");
        return r;
    }
    return tls12 ? verify_probe12_internal(use_fd, ip, port, sni, deadline_ms,
                                            hello_wire, encoding, mark, path)
                 : verify_probe13_on(use_fd, ip, port, sni, deadline_ms,
                                       hello_wire, encoding, mark, path);
}

void d2k_verify_close(d2k_ver_result *r) {
    if (r && r->fd >= 0) {
        close(r->fd);
        r->fd = -1;
    }
}

/* --- то же самое, но по QUIC --------------------------------------------- */

d2k_ver_result d2k_verify_probe_quic(const char *ip, uint16_t port, const char *sni,
                                     int deadline_ms, size_t hello_wire) {
    return d2k_verify_probe_quic_on(-1, ip, port, sni, deadline_ms, hello_wire);
}

/* ЭТАП «РУКОПОЖАТИЕ ПРОШЛО, ПРИЛОЖЕНИЕ МОЛЧИТ» — СВОЕЙ СТРОКОЙ (задача 42).
   Поле 02.10.2026 (задача 33): на части адресов поток обрывается на пути
   сразу после рукопожатия, и прежняя строка «кода ответа HTTP/3 нет»
   читалась как дефект датапата. Это честный отрицательный исход проверки, и
   его этап называется прямо: получено got байт ответа, после запроса пришло
   wire байт датаграмм (ноль — сервер замолчал совсем). closed — причина, если
   соединение закрылось. */
static void quic_app_silent(d2k_ver_result *r, size_t got, uint64_t wire,
                            const char *closed) {
    if (closed) {
        snprintf(r->reason, sizeof r->reason,
                 "рукопожатие прошло, приложение молчит, получено %zu байт; "
                 "соединение закрыто: %.40s", got, closed);
    } else {
        snprintf(r->reason, sizeof r->reason,
                 "рукопожатие прошло, приложение молчит, получено %zu байт "
                 "(после запроса пришло %llu байт)", got, (unsigned long long)wire);
    }
}

/* use_fd — УЖЕ ЗАНЯТЫЙ сокет UDP (d2k_props_bind_udp), под чей местный порт
   поставлен пробный план. Меньше единицы — завести свой. */
d2k_ver_result d2k_verify_probe_quic_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.fd = -1;
    r.name_ok = -1;
    snprintf(r.reason, sizeof r.reason, "проба не начиналась");
    const char *host = (sni && sni[0]) ? sni : ip;
    if (!host || !host[0]) { return r; }
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if (*p <= 32 || *p == 127) {
            snprintf(r.reason, sizeof r.reason, "недопустимый символ в имени");
            return r;
        }
    }

    d2k_qc_opts o;
    memset(&o, 0, sizeof o);
    o.ip = ip;
    o.port = port ? port : 443;
    o.sni = sni;
    o.alpn = "h3";
    o.deadline_ms = deadline_ms > 0 ? deadline_ms : 5000;
    o.pad_to = hello_wire;
    o.use_fd = use_fd;
    /* Метки НЕТ намеренно — ровно по той же причине, что у TCP-зонда: к
       помеченному пакету поставленный план не применится, и зонд мерил бы
       линию БЕЗ обхода, считая, что мерит с обходом. */

    d2k_qc *c = NULL;
    char err[200];
    err[0] = '\0';
    if (d2k_qc_connect(&o, &c, err, sizeof err) != 0) {
        /* Транспорт у QUIC не «встал» отдельно от рукопожатия: датаграмма
           уходит всегда, и отличить «ушла в никуда» от «ушла и не понравилась»
           можно только по тому, ответил ли сервер хоть чем-то. Оба случая для
           нас — «не измерено», и приписывать им уровень транспорта значило бы
           дописать доказательство. */
        snprintf(r.reason, sizeof r.reason, "рукопожатия нет: %.150s", err);
        return r;
    }
    r.level = D2K_VER_HANDSHAKE;
    r.name_ok = d2k_qc_peer_name(c);
    d2k_qc_local_addr(c, r.local_addr, &r.family, &r.local_port);
    if (r.family == 4) memcpy(r.local_ip4, r.local_addr, 4);
    r.fd = d2k_qc_fd(c);
    snprintf(r.reason, sizeof r.reason, "рукопожатие завершено, приложение молчит");

    /* Управляющий поток обязателен: без SETTINGS сервер вправе не отвечать
       вовсе, и молчание записалось бы блокировкой. */
    uint8_t ctl[16];
    size_t cn = d2k_h3_control(ctl, sizeof ctl);
    if (cn == 0 || d2k_qc_stream_send(c, 2, ctl, cn, 0, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "управляющий поток не ушёл: %.140s", err);
        r.fd = d2k_qc_release(c);
        return r;
    }
    /* Пауза между управляющим потоком и вопросом. Измерено 13.09.2026 на
       живых серверах: без неё отвечает только один стек из четырёх — сервер
       обязан увидеть SETTINGS раньше запроса, а за это же время доезжает его
       NEW_CONNECTION_ID и меняется адрес ответа. */
    {
        uint64_t sid = 0;
        uint8_t drop[2048];
        (void)d2k_qc_stream_recv(c, &sid, drop, sizeof drop, 400, err, sizeof err);
    }

    uint8_t req[512];
    size_t rn = d2k_h3_request(host, "/", req, sizeof req);
    if (rn == 0 || d2k_qc_stream_send(c, 0, req, rn, 1, err, sizeof err) != 0) {
        snprintf(r.reason, sizeof r.reason, "запрос не ушёл: %.150s", err);
        r.fd = d2k_qc_release(c);
        return r;
    }

    uint8_t rx[8192];
    size_t got = 0;
    int closed = 0;
    uint64_t wire_before = d2k_qc_rx_wire_bytes(c);
    int64_t until = verify_now_ms() + (deadline_ms > 0 ? deadline_ms : 5000);
    while (got < sizeof rx && verify_now_ms() < until) {
        uint64_t sid = 0;
        /* Куски по 200 мс безопасны: срок повтора запроса живёт в соединении
           (d2k_qc_stream_recv), а не в куске. */
        long n = d2k_qc_stream_recv(c, &sid, rx + got, sizeof rx - got, 200,
                                    err, sizeof err);
        if (n < 0) { closed = 1; break; }
        if (n > 0) { got += (size_t)n; }
        int st = 0;
        if (got > 0 && d2k_h3_status(rx, got, &st) == 0) {
            r.status = st;
            if (st == 451) {
                r.level = D2K_VER_DENIED;
                r.http_outcome = D2K_HTTP_LEGAL_DENIAL;
                snprintf(r.http_evidence, sizeof r.http_evidence, "HTTP 451");
                snprintf(r.reason, sizeof r.reason, "HTTP отказ: HTTP 451");
            }
            break;
        }
    }
    /* ЗАГОЛОВКИ — ЕЩЁ НЕ ПРИЛОЖЕНИЕ (задача 39). Поле 02.10.2026 (задача 33):
       после фальшивки линия пропускает рукопожатие и первые килобайты, а
       дальше поток обрывается. Приложение доказано, когда ответ пришёл
       ЦЕЛИКОМ (сервер закрыл поток — как полный ответ у TCP-зонда) или когда
       через линию прошло не меньше D2K_QUIC_ARM_DATA_BYTES данных ответа.
       Чтение продолжается в том же сроке; лишние байты не храним. */
    if (r.status != 0 && r.level != D2K_VER_DENIED) {
        uint64_t bytes = 0;
        int fin = 0;
        d2k_qc_app_progress(c, &bytes, &fin);
        while (!closed && !fin && bytes < D2K_QUIC_ARM_DATA_BYTES &&
               verify_now_ms() < until) {
            uint64_t sid = 0;
            uint8_t sink[4096];
            if (d2k_qc_stream_recv(c, &sid, sink, sizeof sink, 200, err, sizeof err) < 0) {
                closed = 1;
            }
            d2k_qc_app_progress(c, &bytes, &fin);
        }
        r.body_bytes = bytes;
        r.body_complete = fin;
        if (fin || bytes >= D2K_QUIC_ARM_DATA_BYTES) {
            r.level = D2K_VER_APPLICATION;
            snprintf(r.reason, sizeof r.reason,
                     "заголовки HTTP/3 получены, статус %d, данных %llu байт%s", r.status,
                     (unsigned long long)bytes, fin ? ", ответ целиком" : "");
        } else {
            snprintf(r.reason, sizeof r.reason,
                     "заголовки HTTP/3 получены (статус %d), поток оборван на %llu байт "
                     "до %u и до конца ответа%s%.60s", r.status, (unsigned long long)bytes,
                     D2K_QUIC_ARM_DATA_BYTES, closed ? ": " : "", closed ? err : "");
        }
    } else if (r.level != D2K_VER_DENIED) {
        quic_app_silent(&r, got, d2k_qc_rx_wire_bytes(c) - wire_before,
                        closed ? err : NULL);
    }
    /* Сокет остаётся ОТКРЫТЫМ до d2k_verify_close — по той же причине, что у
       TCP-зонда: закрытие удаляет ячейку потока в датапате раньше, чем придёт
       событие применения плана. */
    r.fd = d2k_qc_release(c);
    return r;
}
