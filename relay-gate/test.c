/* Тесты d2k-gate без сети: разбор, список, пересборка, адреса, частота и
   путь отказа через пару сокетов. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define main gate_program_main
#include "main.c"
#undef main
#include <assert.h>

static int parse(const char *s, gate_req *r) { return parse_head(s, strlen(s), r); }

static void test_hosts(void) {
    assert(host_allowed("raw.githubusercontent.com"));
    assert(host_allowed("RAW.GitHubUserContent.com"));
    assert(host_allowed("bin.entware.net."));
    assert(host_allowed("downloads.openwrt.org"));
    assert(!host_allowed("githubusercontent.com"));
    assert(!host_allowed("evil.raw.githubusercontent.com"));
    assert(!host_allowed("raw.githubusercontent.com.attacker.net"));
    assert(!host_allowed("140.82.121.4"));
    assert(!host_allowed(""));
}

static void test_parse(void) {
    gate_req r;
    assert(parse("CONNECT raw.githubusercontent.com:443 HTTP/1.1\r\nHost: x\r\n\r\n", &r) == 0);
    assert(r.kind == REQ_CONNECT && !strcmp(r.host, "raw.githubusercontent.com") && r.port == 443);
    assert(parse("CONNECT raw.githubusercontent.com:443 HTTP/1.1\r\nHost: x\r\n", &r) == -1);
    assert(parse("GET http://bin.entware.net/aarch64-k3.10/Packages.gz HTTP/1.1\r\nHost: bin.entware.net\r\n\r\n", &r) == 0);
    assert(r.kind == REQ_PLAIN && !strcmp(r.host, "bin.entware.net") && r.port == 80 &&
           !strcmp(r.path, "/aarch64-k3.10/Packages.gz"));
    assert(parse("GET http://bin.entware.net HTTP/1.0\r\n\r\n", &r) == 0 && !strcmp(r.path, "/"));
    assert(parse("GET /x HTTP/1.1\r\n\r\n", &r) == -2);                       /* не прокси-запрос */
    assert(parse("POST http://bin.entware.net/ HTTP/1.1\r\n\r\n", &r) == -2);
    assert(parse("CONNECT github.com HTTP/1.1\r\n\r\n", &r) == -2);           /* без порта */
    assert(parse("CONNECT user@github.com:443 HTTP/1.1\r\n\r\n", &r) == -2);
    assert(parse("CONNECT github.com:443 HTTP/2\r\n\r\n", &r) == -2);
    assert(parse("CONNECT github.com:99999 HTTP/1.1\r\n\r\n", &r) == -2);
}

static void test_allowed(void) {
    gate_req r;
    assert(parse("CONNECT github.com:443 HTTP/1.1\r\n\r\n", &r) == 0 && request_allowed(&r));
    assert(parse("CONNECT github.com:22 HTTP/1.1\r\n\r\n", &r) == 0 && !request_allowed(&r));
    assert(parse("CONNECT example.com:443 HTTP/1.1\r\n\r\n", &r) == 0 && !request_allowed(&r));
    assert(parse("CONNECT 140.82.121.4:443 HTTP/1.1\r\n\r\n", &r) == 0 && !request_allowed(&r));
    assert(parse("GET http://bin.entware.net/x HTTP/1.1\r\n\r\n", &r) == 0 && request_allowed(&r));
    assert(parse("GET http://bin.entware.net:8080/x HTTP/1.1\r\n\r\n", &r) == 0 && !request_allowed(&r));
    assert(parse("GET http://example.com/ HTTP/1.1\r\n\r\n", &r) == 0 && !request_allowed(&r));
}

static void test_rebuild(void) {
    const char *h = "GET http://bin.entware.net/a/b.ipk HTTP/1.1\r\n"
                    "Host: bin.entware.net\r\nUser-Agent: opkg\r\nProxy-Connection: keep-alive\r\n"
                    "Connection: keep-alive\r\nAccept: */*\r\n\r\n";
    gate_req r; char out[2048];
    assert(parse(h, &r) == 0);
    long n = build_origin_request(&r, h, out, sizeof out);
    assert(n > 0); out[n] = '\0';
    const char *want = "GET /a/b.ipk HTTP/1.1\r\nHost: bin.entware.net\r\n";
    assert(!strncmp(out, want, strlen(want)));
    assert(strstr(out, "User-Agent: opkg\r\n") && strstr(out, "Accept: */*\r\n"));
    assert(!strstr(out, "Proxy-Connection") && !strstr(out, "keep-alive"));
    assert(strstr(out, "Connection: close\r\n\r\n") && out[n - 1] == '\n');
    char tiny[32];
    assert(build_origin_request(&r, h, tiny, sizeof tiny) == -1);
}

static int pub4(const char *ip) {
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &a.sin_addr); return addr_public((struct sockaddr *)&a);
}
static int pub6(const char *ip) {
    struct sockaddr_in6 a; memset(&a, 0, sizeof a); a.sin6_family = AF_INET6;
    inet_pton(AF_INET6, ip, &a.sin6_addr); return addr_public((struct sockaddr *)&a);
}

static void test_addresses(void) {
    assert(pub4("140.82.121.4") && pub4("8.8.8.8"));
    assert(!pub4("10.1.2.3") && !pub4("127.0.0.1") && !pub4("192.168.1.1") && !pub4("172.16.0.1") &&
           !pub4("172.31.255.1") && !pub4("169.254.1.1") && !pub4("100.64.0.1") && !pub4("0.0.0.0") &&
           !pub4("224.0.0.1"));
    assert(pub4("172.32.0.1") && pub4("100.128.0.1"));
    assert(pub6("2606:4700::1"));
    assert(!pub6("::1") && !pub6("::") && !pub6("fe80::1") && !pub6("fd00::1") && !pub6("ff02::1") &&
           !pub6("::ffff:10.0.0.1"));
    assert(pub6("::ffff:8.8.8.8"));
}

static void test_rate(void) {
    rate_limit *l = calloc(1, sizeof *l); assert(l);
    pthread_mutex_init(&l->mu, NULL);
    for (int i = 0; i < PER_IP_PER_MIN; i++) assert(rate_allow(l, 0x01020304, 600));
    assert(!rate_allow(l, 0x01020304, 600));
    assert(rate_allow(l, 0x01020305, 600));
    assert(rate_allow(l, 0x01020304, 660));        /* новая минута */
    free(l);
}

static void refused_with(const char *request, const char *status) {
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    conn_arg *c = calloc(1, sizeof *c); assert(c);
    c->fd = sv[1]; c->peer.sin_family = AF_INET;
    atomic_fetch_add(&active, 1);
    assert(write_all(sv[0], request, strlen(request)) == 0);
    serve(c);
    char b[256] = ""; ssize_t n = recv(sv[0], b, sizeof b - 1, 0);
    assert(n > 0); b[n] = '\0';
    assert(!strncmp(b, status, strlen(status)));
    assert(atomic_load(&active) == 0);
    close(sv[0]);
}

int main(void) {
    test_hosts(); test_parse(); test_allowed(); test_rebuild(); test_addresses(); test_rate();
    refused_with("CONNECT example.com:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 403");
    refused_with("CONNECT github.com:22 HTTP/1.1\r\n\r\n", "HTTP/1.1 403");
    refused_with("GET /x HTTP/1.1\r\n\r\n", "HTTP/1.1 400");
    puts("d2k-gate: все проверки прошли");
    return 0;
}
