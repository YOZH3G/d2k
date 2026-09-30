/* Exercise production TX/RX sequencing. TCP is localhost-only; TLS and
 * baseline replies are deterministic, so no public service is probed. */
#include "volume.c"

static int failures, legacy_calls, modern_calls, baseline_calls;
static int expected_legacy;
static const char *expected_path;
static size_t expected_wire;
static int mark_calls;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "volume-context:%d: %s\n", __LINE__, #c); failures++; } } while (0)

static int mark_ok(int fd, uint32_t mark) {
    (void)fd; CHECK(mark == 0x2f); mark_calls++; return 0;
}
d2k_mark_fn d2k_mark_hook = mark_ok;

int d2k_tls_connect(int fd, const char *sni, int ms, size_t wire,
                    d2k_tls **out, char *err, size_t cap) {
    (void)fd; (void)sni; (void)ms; *out = NULL;
    CHECK(!expected_legacy && wire == expected_wire); modern_calls++;
    snprintf(err, cap, "TX reset"); return -1;
}
int d2k_tls12_connect(int fd, const char *sni, int ms, size_t wire,
                      d2k_tls12 **out, char *err, size_t cap) {
    (void)fd; (void)sni; (void)ms; *out = NULL;
    CHECK(expected_legacy && wire == expected_wire); legacy_calls++;
    snprintf(err, cap, "TX reset"); return -1;
}
int d2k_tls_write(d2k_tls *t, const uint8_t *b, size_t n, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)e; (void)c; CHECK(0); return -1;
}
int d2k_tls12_write(d2k_tls12 *t, const uint8_t *b, size_t n, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)e; (void)c; CHECK(0); return -1;
}
long d2k_tls_read(d2k_tls *t, uint8_t *b, size_t n, int ms, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)ms; (void)e; (void)c; CHECK(0); return -1;
}
long d2k_tls12_read(d2k_tls12 *t, uint8_t *b, size_t n, int ms, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)ms; (void)e; (void)c; CHECK(0); return -1;
}
void d2k_tls_free(d2k_tls *t) { (void)t; CHECK(0); }
void d2k_tls12_free(d2k_tls12 *t) { (void)t; CHECK(0); }

d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
    const char *sni, int ms, size_t wire, int legacy, int encoding, uint32_t mark) {
    (void)ip; (void)port; (void)ms;
    CHECK(strcmp(sni, "context.test") == 0 && legacy == expected_legacy &&
          wire == expected_wire && mark == 0x2f);
    CHECK(encoding == (baseline_calls == 2));
    d2k_ver_result r = {0};
    r.fd = -1; r.status = 200; r.body_has_length = 1;
    r.body_framing_valid = 1; r.body_expected = 96460;
    r.body_bytes = 23900 + baseline_calls * 10;
    if (encoding) {
        r.body_bytes = r.body_expected = 18000;
        r.body_complete = 1; r.body_encoding = 1;
    }
    baseline_calls++;
    return r;
}
void d2k_verify_close(d2k_ver_result *r) { CHECK(r->fd == -1); }

d2k_ver_result d2k_verify_probe_path_on(int fd, const char *ip, uint16_t port,
    const char *sni, int ms, size_t wire, int legacy, int encoding,
    uint32_t mark, const char *path) {
    CHECK(fd == -1 && (expected_path ? path && !strcmp(path, expected_path) : !path));
    return d2k_verify_probe_baseline(ip, port, sni, ms, wire, legacy, encoding, mark);
}

int main(void) {
    for (int family = 4; family <= 6; family += 2) {
    for (int legacy = 0; legacy <= 1; legacy++) {
    for (int resource = 0; resource <= 1; resource++) {
        int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        struct sockaddr_storage addr = {0};
        socklen_t len;
        const char *ip;
        if (family == 6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
            a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback;
            len = sizeof *a; ip = "::1";
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&addr;
            a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(0x7f000001u);
            len = sizeof *a; ip = "127.0.0.1";
        }
        CHECK(fd >= 0 && bind(fd, (struct sockaddr *)&addr, len) == 0);
        CHECK(getsockname(fd, (struct sockaddr *)&addr, &len) == 0 && listen(fd, 2) == 0);
        uint16_t port = family == 6
            ? ntohs(((struct sockaddr_in6 *)&addr)->sin6_port)
            : ntohs(((struct sockaddr_in *)&addr)->sin_port);
        expected_legacy = legacy; expected_wire = legacy ? 512 : 1489;
        baseline_calls = 0;
        expected_path = resource ? "/public/main.css" : NULL;
        d2k_vol_result r = resource
            ? d2k_volume_probe_path(ip, port, "context.test", 0, legacy,
                                    expected_wire, 0x2f, expected_path)
            : d2k_volume_probe(ip, port, "context.test", 0, legacy, expected_wire, 0x2f);
        CHECK(r.verdict == D2K_VOL_UNREACHABLE && r.rx_cut &&
              baseline_calls == 3 && r.rx_at_kb == 23);
        close(fd);
    }
    }
    }
    CHECK(modern_calls == 4 && legacy_calls == 4 && mark_calls == 8);
    if (failures) return 1;
    puts("test_volume_context: OK"); return 0;
}
