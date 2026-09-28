/* Isolated Linux veth integration. Fixture creates d2k6out/d2k6peer and a
 * marked route to 2001:db8:2::2 through fe80::fe. No external network used. */
#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include "d2k_ip6frag_send.h"
#include "d2k_ipfrag.h"
int main(int argc, char **argv) {
    uint8_t src[16], dst[16], wire[512], payload[32] = {0};
    assert(inet_pton(AF_INET6, "2001:db8:1::1", src) == 1);
    assert(inet_pton(AF_INET6, "2001:db8:2::2", dst) == 1);
    d2k_ipfrag_plan plan = {.pos1=8, .reverse=1};
    d2k_ipfrag_span spans[3];
    assert(d2k_udpfrag6_build_ex(src, dst, 51234, 443, payload, sizeof payload,
        &plan, 0x12345678, 61, 0x2e, 123, wire, sizeof wire, spans) == 2);
    d2k_ip6frag_sender sender;
    d2k_ip6frag_sender_init(&sender);
    if (argc == 2 && !strcmp(argv[1], "--missing-neighbor")) {
        assert(d2k_ip6frag_prepare(&sender, wire, spans[0].len, 0xd200) < 0);
        assert(errno == EHOSTUNREACH);
        d2k_ip6frag_sender_close(&sender);
        puts("IPv6 fragment: unknown neighbor refused, no guessed MAC"); return 0;
    }
    int receive = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
    assert(receive >= 0);
    struct sockaddr_ll peer = {.sll_family=AF_PACKET, .sll_protocol=htons(ETH_P_IPV6)};
    peer.sll_ifindex = (int)if_nametoindex("d2k6peer");
    assert(peer.sll_ifindex > 0 && bind(receive, (struct sockaddr *)&peer, sizeof peer) == 0);
    for (int i = 0; i < 2; i++) {
        assert(d2k_ip6frag_send(&sender, wire + spans[i].off, spans[i].len, 0xd200) == (ssize_t)spans[i].len);
        struct pollfd ready = {.fd=receive, .events=POLLIN};
        assert(poll(&ready, 1, 1000) == 1);
        uint8_t got[512];
        ssize_t n = recv(receive, got, sizeof got, 0);
        assert(n == (ssize_t)spans[i].len && !memcmp(got, wire + spans[i].off, (size_t)n));
    }
    assert(sender.next.sll_halen == 6);
    const uint8_t mac[6] = {2,0,0,0,6,2};
    assert(!memcmp(sender.next.sll_addr, mac, 6));
    close(receive); d2k_ip6frag_sender_close(&sender);
    puts("IPv6 fragments: marked route, gateway neighbor, Ethernet bytes/order passed");
    return 0;
}
