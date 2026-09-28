/* Native IPv6 application bytes through the lab's real NFQUEUE rules. */
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int readable(int fd) {
    struct pollfd p = {fd, POLLIN, 0};
    return poll(&p, 1, 2000) == 1 && (p.revents & POLLIN);
}

static int exchange(int type) {
    static const char payload[] = "native IPv6 direct traffic";
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback;
    int server = socket(AF_INET6, type, 0);
    int client = socket(AF_INET6, type, 0);
    int peer = -1, ok = 0;
    socklen_t size = sizeof addr;
    char buf[sizeof payload];
    if (server < 0 || client < 0 || bind(server, (void *)&addr, size) ||
        getsockname(server, (void *)&addr, &size)) goto done;
    if (type == SOCK_STREAM && listen(server, 1)) goto done;
    /* SO_SNDTIMEO bounds a connect if a broken queue stops delivering SYN. */
    struct timeval timeout = {2, 0};
    if (setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
        connect(client, (void *)&addr, size)) goto done;
    if (type == SOCK_STREAM) {
        if (!readable(server)) goto done;
        peer = accept(server, NULL, NULL);
        if (peer < 0) goto done;
    } else {
        peer = server;
    }
    if (send(client, payload, sizeof payload, 0) != sizeof payload ||
        !readable(peer)) goto done;
    struct sockaddr_in6 from;
    socklen_t from_size = sizeof from;
    if (recvfrom(peer, buf, sizeof buf, MSG_WAITALL, (void *)&from, &from_size) != sizeof payload ||
        memcmp(buf, payload, sizeof payload)) goto done;
    ssize_t sent = type == SOCK_STREAM ? send(peer, buf, sizeof buf, 0) :
        sendto(peer, buf, sizeof buf, 0, (void *)&from, from_size);
    if (sent != sizeof payload || !readable(client) ||
        recv(client, buf, sizeof buf, MSG_WAITALL) != sizeof payload ||
        memcmp(buf, payload, sizeof payload)) goto done;
    ok = 1;
done:
    if (peer >= 0 && peer != server) close(peer);
    if (server >= 0) close(server);
    if (client >= 0) close(client);
    return ok;
}

int main(void) {
    if (!exchange(SOCK_STREAM) || !exchange(SOCK_DGRAM)) {
        fprintf(stderr, "native IPv6 TCP/UDP exchange failed\n");
        return 1;
    }
    puts("native IPv6 TCP and UDP application bytes: pass");
    return 0;
}
