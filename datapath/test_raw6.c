/* Linux-only real raw IPv6 loopback test; run in an isolated network namespace. */
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "d2k_raw.h"
#include "d2k_wire.h"
#include "d2k_ipfrag.h"

static int fail_option;
int d2k_test_setsockopt(int fd, int level, int option, const void *value, socklen_t len) {
    if ((fail_option == 1 && level == IPPROTO_IPV6 && option == IPV6_HDRINCL) ||
        (fail_option == 2 && level == SOL_SOCKET && option == SO_MARK)) {
        errno = EPERM; return -1;
    }
    return setsockopt(fd, level, option, value, len);
}

int main(void) {
    int receive = socket(AF_INET6, SOCK_DGRAM, 0);
    assert(receive >= 0);
    struct sockaddr_in6 local = {.sin6_family=AF_INET6, .sin6_addr=IN6ADDR_LOOPBACK_INIT};
    assert(bind(receive, (struct sockaddr *)&local, sizeof local) == 0);
    socklen_t sl = sizeof local;
    assert(getsockname(receive, (struct sockaddr *)&local, &sl) == 0);
    d2k_conn c = {.family=6, .ttl=48, .src_port=htons(54322), .dst_port=local.sin6_port};
    c.src_ip6[15] = c.dst_ip6[15] = 1;
    const uint8_t body[] = "native IPv6 raw packet";
    d2k_emit e = {.bytes=body, .len=sizeof body};
    uint8_t packet[256], got[256]; char err[256];
    size_t len = d2k_wire_build_udp(&c, &e, packet, sizeof packet);
    assert(len == 48 + sizeof body);
    d2k_raw *raw = d2k_raw_open(0xd200, "lo", err, sizeof err);
    if (!raw) { fprintf(stderr, "%s\n", err); return 1; }
    for (fail_option = 1; fail_option <= 2; fail_option++) {
        assert(d2k_raw_prepare(raw, packet, len, err, sizeof err) < 0);
        assert(d2k_raw_sent(raw) == 0);
    }
    fail_option = 0;
    assert(d2k_raw_route_maxlen_family(raw, c.dst_ip6, 6) >= 1280);
    if (d2k_raw_prepare(raw, packet, len, err, sizeof err) ||
        d2k_raw_send(raw, packet, len, err, sizeof err)) {
        fprintf(stderr, "%s\n", err); return 1;
    }
    struct pollfd wait = {.fd=receive, .events=POLLIN};
    assert(poll(&wait, 1, 1000) == 1);
    struct sockaddr_in6 peer; sl=sizeof peer;
    assert(recvfrom(receive, got, sizeof got, 0, (struct sockaddr *)&peer, &sl) == sizeof body);
    assert(!memcmp(got, body, sizeof body) && peer.sin6_port == c.src_port);
    assert(!memcmp(&peer.sin6_addr, c.src_ip6, 16));
    assert(d2k_raw_sent(raw) == 1);
    assert(d2k_raw_send(raw, packet, 39, err, sizeof err) < 0);
    int capture = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    assert(capture >= 0);
    struct sockaddr_ll link = {.sll_family=AF_PACKET, .sll_protocol=htons(ETH_P_ALL)};
    link.sll_ifindex = (int)if_nametoindex("lo");
    assert(bind(capture, (struct sockaddr *)&link, sizeof link) == 0);
    for (int reverse = 0; reverse <= 1; reverse++) {
        d2k_ipfrag_plan plan = {.pos1=8, .reverse=(uint8_t)reverse};
        d2k_ipfrag_span spans[3];
        size_t count = d2k_udpfrag6_build_ex(c.src_ip6, c.dst_ip6,
            ntohs(c.src_port), ntohs(c.dst_port), body, sizeof body, &plan,
            0x12345000u + (unsigned)reverse, 48, 0, 0, packet, sizeof packet, spans);
        assert(count == 2);
        for (size_t i = 0; i < count; i++) {
            assert(d2k_raw_prepare(raw, packet + spans[i].off, spans[i].len, err, sizeof err) == 0);
            assert(d2k_raw_send(raw, packet + spans[i].off, spans[i].len, err, sizeof err) == 0);
        }
        int seen = 0;
        for (int attempt = 0; attempt < 32 && seen < 2; attempt++) {
            struct pollfd ready = {.fd=capture, .events=POLLIN};
            if (poll(&ready, 1, 100) <= 0) break;
            uint8_t frame[2048];
            struct sockaddr_ll from; socklen_t flen = sizeof from;
            ssize_t bytes = recvfrom(capture, frame, sizeof frame, 0,
                                     (struct sockaddr *)&from, &flen);
            if (bytes < 48 || from.sll_pkttype != PACKET_OUTGOING ||
                frame[0] >> 4 != 6 || frame[6] != 44 ||
                memcmp(frame + 44, packet + spans[0].off + 44, 4) != 0) continue;
            assert((size_t)bytes == spans[seen].len);
            assert(!memcmp(frame, packet + spans[seen].off, (size_t)bytes));
            seen++;
        }
        assert(seen == 2); /* UDP success alone does not prove wire fragmentation. */
        assert(poll(&wait, 1, 1000) == 1);
        assert(recv(receive, got, sizeof got, 0) == sizeof body);
        assert(!memcmp(got, body, sizeof body));
    }
    close(capture);
    d2k_raw_close(raw); close(receive);
    puts("raw IPv6: marked native packet delivered with correct tuple/checksum");
    return 0;
}
