#ifndef D2K_IP6FRAG_SEND_H
#define D2K_IP6FRAG_SEND_H
/* Shared Linux wire transport for IPv6 fragments. AF_INET6 raw sockets go
 * through LOCAL_OUT defragmentation; AF_PACKET preserves measured bytes/order.
 * Resolve the marked route and next-hop neighbor through the kernel. Never
 * guess a gateway/MAC, broadcast, or substitute an unfragmented datagram. */
#ifdef __linux__
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

typedef struct {
    int fd;
    int mtu;
    uint8_t src[16], dst[16];
    uint32_t mark;
    uint64_t expires;
    struct sockaddr_ll next;
} d2k_ip6frag_sender;

static inline void d2k_ip6frag_sender_init(d2k_ip6frag_sender *s) {
    memset(s, 0, sizeof *s); s->fd = -1;
}
static inline void d2k_ip6frag_sender_close(d2k_ip6frag_sender *s) {
    if (s->fd >= 0) close(s->fd);
    d2k_ip6frag_sender_init(s);
}
static inline uint64_t d2k_f6_now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static inline int d2k_f6_attr(struct nlmsghdr *h, size_t cap, unsigned type,
                              const void *data, size_t len) {
    size_t at = NLMSG_ALIGN(h->nlmsg_len), total = RTA_LENGTH(len);
    if (at + RTA_ALIGN(total) > cap) { errno = EMSGSIZE; return -1; }
    struct rtattr *a = (struct rtattr *)((uint8_t *)h + at);
    a->rta_type = (unsigned short)type; a->rta_len = (unsigned short)total;
    memcpy(RTA_DATA(a), data, len);
    h->nlmsg_len = (uint32_t)(at + RTA_ALIGN(total));
    return 0;
}
static inline ssize_t d2k_f6_query(struct nlmsghdr *req, void *out, size_t cap) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct timeval tv = {0, 200000};
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    socklen_t len = sizeof kernel;
    ssize_t n = -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0 &&
        sendto(fd, req, req->nlmsg_len, 0, (struct sockaddr *)&kernel, len) == (ssize_t)req->nlmsg_len) {
        n = recvfrom(fd, out, cap, 0, (struct sockaddr *)&kernel, &len);
        if (n >= 0 && (len < sizeof kernel || kernel.nl_pid != 0)) {
            errno = EPROTO; n = -1;
        }
    }
    int saved = errno; close(fd); errno = saved;
    return n;
}
static inline int d2k_f6_route(const uint8_t src[16], const uint8_t dst[16],
                               uint32_t mark, int *ifindex, uint8_t gateway[16]) {
    struct { struct nlmsghdr h; struct rtmsg r; uint8_t attrs[96]; } req = {0};
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof req.r);
    req.h.nlmsg_type = RTM_GETROUTE; req.h.nlmsg_flags = NLM_F_REQUEST; req.h.nlmsg_seq = 1;
    req.r.rtm_family = AF_INET6; req.r.rtm_dst_len = req.r.rtm_src_len = 128;
    if (d2k_f6_attr(&req.h, sizeof req, RTA_DST, dst, 16) ||
        d2k_f6_attr(&req.h, sizeof req, RTA_SRC, src, 16) ||
        d2k_f6_attr(&req.h, sizeof req, RTA_MARK, &mark, sizeof mark)) return -1;
    union { struct nlmsghdr align; uint8_t bytes[8192]; } reply;
    ssize_t n = d2k_f6_query(&req.h, reply.bytes, sizeof reply.bytes);
    if (n < 0) return -1;
    memcpy(gateway, dst, 16); *ifindex = 0;
    for (struct nlmsghdr *h = (struct nlmsghdr *)reply.bytes; n >= 0 && NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
        if (h->nlmsg_seq != 1) continue;
        if (h->nlmsg_type == NLMSG_ERROR) {
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) break;
            int error = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
            errno = error < 0 ? -error : EPROTO; return -1;
        }
        if (h->nlmsg_type != RTM_NEWROUTE || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) continue;
        struct rtmsg *r = NLMSG_DATA(h);
        if (r->rtm_family != AF_INET6 || (r->rtm_type != RTN_UNICAST && r->rtm_type != RTN_LOCAL)) break;
        int left = (int)RTM_PAYLOAD(h);
        for (struct rtattr *a = RTM_RTA(r); RTA_OK(a, left); a = RTA_NEXT(a, left)) {
            if (a->rta_type == RTA_OIF && RTA_PAYLOAD(a) == sizeof *ifindex)
                memcpy(ifindex, RTA_DATA(a), sizeof *ifindex);
            if (a->rta_type == RTA_GATEWAY && RTA_PAYLOAD(a) == 16)
                memcpy(gateway, RTA_DATA(a), 16);
        }
        if (*ifindex > 0) return 0;
    }
    errno = ENETUNREACH; return -1;
}
static inline int d2k_f6_neighbor(int ifindex, const uint8_t gateway[16], uint8_t mac[6]) {
    struct { struct nlmsghdr h; struct ndmsg d; uint8_t attrs[24]; } req = {0};
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof req.d);
    /* Linux 4.9 supports RTM_GETNEIGH dumps, not single-entry GETNEIGH. */
    req.h.nlmsg_type = RTM_GETNEIGH; req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; req.h.nlmsg_seq = 1;
    req.d.ndm_family = AF_INET6; req.d.ndm_ifindex = ifindex;
    union { struct nlmsghdr align; uint8_t bytes[8192]; } reply;
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE), rc = -1;
    if (fd < 0) return -1;
    struct sockaddr_nl kernel = {.nl_family=AF_NETLINK};
    struct timeval tv = {0, 200000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) ||
        sendto(fd, &req, req.h.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof kernel) != (ssize_t)req.h.nlmsg_len)
        goto done;
    uint64_t deadline = d2k_f6_now() + 200;
    for (int batch = 0; batch < 64 && d2k_f6_now() <= deadline; batch++) {
    socklen_t fromlen = sizeof kernel;
    ssize_t n = recvfrom(fd, reply.bytes, sizeof reply.bytes, 0,
                          (struct sockaddr *)&kernel, &fromlen);
    if (n < 0) goto done;
    if (fromlen < sizeof kernel || kernel.nl_pid != 0) { errno = EPROTO; goto done; }
    for (struct nlmsghdr *h = (struct nlmsghdr *)reply.bytes; n >= 0 && NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
        if (h->nlmsg_seq == 1 && (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)) {
            errno = EHOSTUNREACH; goto done;
        }
        if (h->nlmsg_seq != 1 || h->nlmsg_type != RTM_NEWNEIGH ||
            h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ndmsg))) continue;
        struct ndmsg *d = NLMSG_DATA(h);
        if (d->ndm_family != AF_INET6 || d->ndm_ifindex != ifindex ||
            !(d->ndm_state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT))) continue;
        int left = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof *d);
        int dst_ok = 0, mac_ok = 0;
        struct rtattr *a = (struct rtattr *)((uint8_t *)d + NLMSG_ALIGN(sizeof *d));
        for (; RTA_OK(a, left); a = RTA_NEXT(a, left)) {
            if (a->rta_type == NDA_DST && RTA_PAYLOAD(a) == 16)
                dst_ok = memcmp(RTA_DATA(a), gateway, 16) == 0;
            if (a->rta_type == NDA_LLADDR && RTA_PAYLOAD(a) == 6) {
                memcpy(mac, RTA_DATA(a), 6); mac_ok = 1;
            }
        }
        if (dst_ok && mac_ok) { rc = 0; goto done; }
    }
    }
    errno = EHOSTUNREACH;
done:
    { int saved = errno; close(fd); errno = saved; }
    return rc;
}
static inline int d2k_ip6frag_prepare(d2k_ip6frag_sender *s, const uint8_t *packet,
                                      size_t len, uint32_t mark) {
    if (!packet || len < 48 || packet[0] >> 4 != 6 || packet[6] != 44 ||
        len != 40u + (size_t)packet[4] * 256 + packet[5]) { errno = EINVAL; return -1; }
    uint64_t now = d2k_f6_now();
    if (s->fd >= 0 && now && now < s->expires && s->mark == mark &&
        !memcmp(s->src, packet + 8, 16) && !memcmp(s->dst, packet + 24, 16)) {
        if (len <= (size_t)s->mtu) return 0;
        errno = EMSGSIZE; return -1;
    }
    s->expires = 0;
    int index;
    uint8_t gateway[16];
    if (d2k_f6_route(packet + 8, packet + 24, mark, &index, gateway)) return -1;
    if (s->fd < 0) {
        s->fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
        if (s->fd < 0) return -1;
    }
    if (setsockopt(s->fd, SOL_SOCKET, SO_MARK, &mark, sizeof mark)) return -1;
    struct ifreq dev;
    memset(&dev, 0, sizeof dev);
    if (!if_indextoname((unsigned)index, dev.ifr_name) || ioctl(s->fd, SIOCGIFFLAGS, &dev)) return -1;
    short flags = dev.ifr_flags;
    if (!(flags & IFF_UP)) { errno = ENETDOWN; return -1; }
    if (ioctl(s->fd, SIOCGIFMTU, &dev)) return -1;
    s->mtu = dev.ifr_mtu;
    if (s->mtu < 1280 || len > (size_t)s->mtu) { errno = EMSGSIZE; return -1; }
    if (ioctl(s->fd, SIOCGIFHWADDR, &dev)) return -1;
    memset(&s->next, 0, sizeof s->next);
    s->next.sll_family = AF_PACKET; s->next.sll_protocol = htons(ETH_P_IPV6);
    s->next.sll_ifindex = index;
    if (dev.ifr_hwaddr.sa_family == ARPHRD_ETHER && !(flags & IFF_NOARP)) {
        if (d2k_f6_neighbor(index, gateway, s->next.sll_addr)) return -1;
        s->next.sll_halen = 6;
    } else if (!(flags & (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_NOARP))) {
        errno = EAFNOSUPPORT; return -1;
    }
    memcpy(s->src, packet + 8, 16); memcpy(s->dst, packet + 24, 16);
    s->mark = mark; s->expires = now ? now + 1000 : 0;
    return 0;
}
static inline ssize_t d2k_ip6frag_send(d2k_ip6frag_sender *s, const uint8_t *packet,
                                       size_t len, uint32_t mark) {
    if (d2k_ip6frag_prepare(s, packet, len, mark)) return -1;
    ssize_t n;
    do { n = sendto(s->fd, packet, len, 0, (struct sockaddr *)&s->next, sizeof s->next); }
    while (n < 0 && errno == EINTR);
    if (n != (ssize_t)len) { s->expires = 0; if (n >= 0) errno = EIO; return -1; }
    return n;
}
#endif
#endif
