/* Exercise the actual raw-layer helpers without raw sockets, iptables or
 * network traffic. Only recvfrom is replaced, with two in-memory packets.
 * This runs the helper code on the host; cross/runtime Linux checks remain
 * separate from these deterministic ownership/wire-format assertions. */
#define _DARWIN_C_SOURCE 1
#define D2K_RAW_UNIT_TEST 1
#include <sys/socket.h>
#include <sys/types.h>
static ssize_t raw_test_sendto(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t);
ssize_t raw_test_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
#define recvfrom raw_test_recvfrom
#define sendto raw_test_sendto
#include "raw.c"
#undef recvfrom
#undef sendto
#include "d2k_wire.h"

#define WORKERS 16
#define PORTS_PER_WORKER 128
static uint16_t ports[WORKERS][PORTS_PER_WORKER];
static uint8_t incoming[2][128];
static size_t incoming_len[2];
static unsigned incoming_noise;
static uint8_t incoming_src[2][16];
static uint8_t outgoing[4][2048];
static size_t outgoing_len[4];
static size_t outgoing_count;
static int failures;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "raw:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

static ssize_t raw_test_sendto(int fd, const void *buf, size_t len, int flags,
                               const struct sockaddr *addr, socklen_t alen)
{
    (void)fd; (void)flags; (void)addr; (void)alen;
    if (outgoing_count >= 4 || len > sizeof outgoing[0]) { return -1; }
    memcpy(outgoing[outgoing_count], buf, len);
    outgoing_len[outgoing_count++] = len;
    return (ssize_t)len;
}

static void test_disorder_pos2_emits_exact_reverse_segments(void)
{
    raw_conn c;
    d2k_trigger tr;
    static const uint8_t bytes[] = {0x16, 0x03, 0x01, 0xaa, 0xbb, 0xcc};
    memset(&c, 0, sizeof c); memset(&tr, 0, sizeof tr);
    c.family = 4; c.send_fd = 1; c.seq = 1000; c.ack = 900;
    c.sport = 41000; c.dport = 443; c.src[0] = 192; c.dst[0] = 198;
    memcpy(c.src + 1, (uint8_t[]){0, 2, 1}, 3);
    memcpy(c.dst + 1, (uint8_t[]){51, 100, 7}, 3);
    memcpy(tr.payload, bytes, sizeof bytes); tr.len = sizeof bytes;
    outgoing_count = 0; memset(outgoing_len, 0, sizeof outgoing_len);
    CHECK(raw_send_disorder_pos(&c, &tr, 1000, 2) == 0);
    CHECK(outgoing_count == 2);
    if (outgoing_count == 2) {
        CHECK(rd32(outgoing[0] + 24) == 1002 && outgoing_len[0] == 44 &&
              memcmp(outgoing[0] + 40, bytes + 2, 4) == 0);
        CHECK(rd32(outgoing[1] + 24) == 1000 && outgoing_len[1] == 42 &&
              memcmp(outgoing[1] + 40, bytes, 2) == 0);
        CHECK((outgoing[0][33] & TCP_PSH) && (outgoing[1][33] & TCP_PSH));
    }
}

ssize_t raw_test_recvfrom(int fd, void *buf, size_t len, int flags,
                         struct sockaddr *addr, socklen_t *alen)
{
    (void)flags;
    if (fd < 0 || fd > 1 || incoming_len[fd] > len) { return -1; }
    memcpy(buf, incoming[fd], incoming_len[fd]);
    if (incoming_noise) {
        struct timespec pause = {0, 3000000};
        incoming_noise--;
        ((uint8_t *)buf)[12] ^= 1; /* IPv4 packet from an unrelated peer */
        nanosleep(&pause, NULL);
    }
    if (addr && alen && *alen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 peer = {0};
        peer.sin6_family = AF_INET6;
        memcpy(&peer.sin6_addr, incoming_src[fd], 16);
        memcpy(addr, &peer, sizeof peer);
        *alen = sizeof peer;
    }
    return (ssize_t)incoming_len[fd];
}

static void test_checksum_matches_original(void)
{
    uint8_t src[] = {192, 0, 2, 1}, dst[] = {198, 51, 100, 7};
    uint8_t *tcp = malloc(65535), *ph = calloc(1, 12 + 65535);
    const size_t sizes[] = {20, 21, 40, 333, 1448, 2048, 65535};
    CHECK(tcp && ph);
    if (!tcp || !ph) { free(tcp); free(ph); return; }
    for (size_t i = 0; i < 65535; i++) { tcp[i] = (uint8_t)(i * 37u + 19u); }
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        size_t n = sizes[k];
        memcpy(ph, src, 4); memcpy(ph + 4, dst, 4);
        ph[9] = 6;
        wr16(ph + 10, (uint16_t)n);
        memcpy(ph + 12, tcp, n);
        ph[28] = ph[29] = 0;
        CHECK(tcp_checksum(src, dst, tcp, n) == checksum(ph, n + 12));
    }
    free(tcp); free(ph);
}

static void test_receive_is_owned_by_connection(void)
{
    raw_conn c[2];
    d2k_poison p;
    const uint8_t *first = NULL, *second = NULL;
    size_t len;
    uint8_t flags;
    uint32_t seq, ack;
    memset(c, 0, sizeof c); memset(&p, 0, sizeof p);
    for (int i = 0; i < 2; i++) {
        uint8_t body[4] = {(uint8_t)(0xa0 + i), 2, 3, 4};
        c[i].buffers = malloc(sizeof(*c[i].buffers));
        CHECK(c[i].buffers != NULL);
        if (!c[i].buffers) { exit(2); }
        c[i].send_fd = -1; c[i].recv_fd = i;
        c[i].sport = (uint16_t)(35000 + i); c[i].dport = 443;
        c[i].src[0] = 192; c[i].dst[0] = 198;
        incoming_len[i] = build_ipv4_tcp(incoming[i], sizeof incoming[i],
            c[i].dst, c[i].src, c[i].dport, c[i].sport, 1, 2, TCP_ACK,
            body, sizeof body, &p, NULL, 0);
        CHECK(incoming_len[i] > 0);
    }
    CHECK(raw_recv(&c[0], &flags, &seq, &ack, &first, &len, d2k_now_ms() + 1000, NULL) == 0 && len == 4);
    CHECK(raw_recv(&c[1], &flags, &seq, &ack, &second, &len, d2k_now_ms() + 1000, NULL) == 0 && len == 4);
    CHECK(first && second && first != second);
    CHECK(first && first[0] == 0xa0); /* must survive the OTHER receive */
    CHECK(second && second[0] == 0xa1);
    for (int i = 0; i < 2; i++) {
        c[i].recv_fd = -1; /* mock identifiers are not owned OS descriptors */
        raw_close(&c[i]);
        CHECK(c[i].buffers == NULL);
    }
}

/* A stream of unrelated packets must not reset the probe deadline. The old
 * raw_recv loop consumed all 20 and accepted a response after the deadline. */
static void test_unrelated_packets_do_not_extend_deadline(void)
{
    raw_conn c = {0};
    d2k_poison p = {0};
    uint8_t body[] = {1, 2, 3}, result[16];
    size_t result_len = 0;
    c.family = 4; c.recv_fd = 0; c.sport = 35000; c.dport = 443;
    c.src[0] = 192; c.dst[0] = 198;
    c.buffers = malloc(sizeof *c.buffers);
    CHECK(c.buffers != NULL);
    if (!c.buffers) return;
    incoming_len[0] = build_ipv4_tcp(incoming[0], sizeof incoming[0],
        c.dst, c.src, c.dport, c.sport, 1, 2, TCP_ACK,
        body, sizeof body, &p, NULL, 0);
    incoming_noise = 20;
    CHECK(raw_read_payload(&c, 5, NULL, result, sizeof result, &result_len) == -1);
    CHECK(result_len == 0);
    incoming_noise = 0;
    free(c.buffers);
}

static void *allocate_ports(void *arg)
{
    int i = *(int *)arg;
    for (int k = 0; k < PORTS_PER_WORKER; k++) { ports[i][k] = next_source_port(); }
    return NULL;
}

static void test_concurrent_ports_are_unique(void)
{
    pthread_t threads[WORKERS];
    int ids[WORKERS];
    uint8_t seen[25000] = {0};
    for (int i = 0; i < WORKERS; i++) {
        ids[i] = i;
        if (pthread_create(&threads[i], NULL, allocate_ports, &ids[i])) { exit(2); }
    }
    for (int i = 0; i < WORKERS; i++) { pthread_join(threads[i], NULL); }
    for (int i = 0; i < WORKERS; i++) {
        for (int k = 0; k < PORTS_PER_WORKER; k++) {
            unsigned p = ports[i][k];
            CHECK(p >= 30000 && p < 55000);
            if (p >= 30000 && p < 55000) { CHECK(!seen[p - 30000]++); }
        }
    }
}

/* Compare the TWO real packet encoders. Only the random IP ID and its
 * dependent IPv4 checksum are normalized; all TCP bytes must match. */
static void test_datapath_matches_raw_headers(void)
{
    uint8_t src[] = {192,0,2,1}, dst[] = {198,51,100,7};
    uint8_t body[1400], a[1600], b[1600];
    for (size_t i = 0; i < sizeof body; i++) { body[i] = (uint8_t)(i * 17); }
    for (unsigned flags = 0; flags < 32; flags++) {
        d2k_poison p = {0}; d2k_emit e = {0}; d2k_conn c = {0};
        p.badsum = !!(flags & 1); p.tcp_ts = !!(flags & 2);
        p.ip_id_zero = !!(flags & 4); p.ttl = flags & 8 ? 8 : 0;
        e.poison = (uint8_t)(flags & 7); e.ttl = (uint8_t)p.ttl;
        e.seq = 123456; e.seq_shift = flags & 16 ? -66000 : 0;
        e.wire_profile = D2K_WIRE_DETECT_TCP;
        e.pre = body; e.pre_len = 101; e.bytes = body + 101; e.len = 1299;
        memcpy(&c.src_ip, src, 4); memcpy(&c.dst_ip, dst, 4);
        uint8_t ports[] = {0x9c,0x40,0x01,0xbb};
        memcpy(&c.src_port, ports, 2); memcpy(&c.dst_port, ports + 2, 2);
        c.ack = 7654321; c.window = 77; c.ttl = 11; c.ip_id = 900;
        size_t an = build_ipv4_tcp(a, sizeof a, src, dst, 40000, 443,
            e.seq + (uint32_t)e.seq_shift, c.ack, TCP_PSH | TCP_ACK,
            body, sizeof body, &p, NULL, 0);
        size_t bn = d2k_wire_build(&c, &e, b, sizeof b);
        CHECK(an > 0 && an == bn);
        CHECK(checksum(b, 20) == 0);
        if (p.ip_id_zero) { CHECK(b[4] == 0 && b[5] == 0); }
        /* IP IDs are per-send random draws, not an arm parameter. */
        memcpy(a + 4, b + 4, 2); a[10] = a[11] = 0;
        wr16(a + 10, checksum(a, 20));
        CHECK(an == bn && memcmp(a, b, an) == 0);
    }
}

int main(void)
{
    {
        uint8_t src[16] = {0x20, 1}, dst[16] = {0x20, 1};
        src[15] = 1; dst[15] = 2;
        uint8_t packet[256], body[] = {1, 2, 3};
        d2k_poison p = {0};
        size_t n = build_ip_tcp(packet, sizeof packet, 6, src, dst, 1000, 443,
                                42, 43, TCP_ACK, body, sizeof body, &p, NULL, 0);
        CHECK(n == 63 && packet[0] == 0x60 && packet[6] == 6);
        CHECK(memcmp(packet + 8, src, 16) == 0 && memcmp(packet + 24, dst, 16) == 0);
        CHECK(d2k_wire_tcp_checksum_ok(packet, n));
        raw_conn conn = {0};
        conn.family = 6; conn.recv_fd = 0; conn.sport = 443; conn.dport = 1000;
        conn.buffers = malloc(sizeof *conn.buffers);
        CHECK(conn.buffers != NULL);
        if (!conn.buffers) return 1;
        memcpy(conn.dst, src, 16);
        memcpy(incoming_src[0], src, 16);
        memcpy(incoming[0], packet + 40, n - 40); incoming_len[0] = n - 40;
        uint8_t flags;
        uint32_t seq, ack;
        const uint8_t *received = NULL;
        size_t received_len = 0;
        CHECK(raw_recv(&conn, &flags, &seq, &ack, &received, &received_len, d2k_now_ms() + 1000, NULL) == 0);
        CHECK(flags == TCP_ACK && seq == 42 && ack == 43);
        CHECK(received_len == sizeof body && memcmp(received, body, sizeof body) == 0);
        free(conn.buffers);
        p.badsum = 1;
        n = build_ip_tcp(packet, sizeof packet, 6, src, dst, 1000, 443,
                         42, 43, TCP_ACK, body, sizeof body, &p, NULL, 0);
        CHECK(n == 63 && !d2k_wire_tcp_checksum_ok(packet, n));
        p.ip_id_zero = 1;
        CHECK(build_ip_tcp(packet, sizeof packet, 6, src, dst, 1000, 443,
                            42, 43, TCP_ACK, body, sizeof body, &p, NULL, 0) == 0);
    }
    test_concurrent_ports_are_unique();
    test_checksum_matches_original();
    test_receive_is_owned_by_connection();
    test_unrelated_packets_do_not_extend_deadline();
    test_datapath_matches_raw_headers();
    test_disorder_pos2_emits_exact_reverse_segments();
    if (failures) { return 1; }
    puts("raw: checksum, connection-owned receives and concurrent ports passed (no network)");
    return 0;
}
