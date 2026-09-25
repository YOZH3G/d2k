#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "d2k_quicprobe.h"
#include "d2k_quic.h"
#include "d2k_quichello.h"
#include "d2k_quic_arms.h"

#define REPEATS 3
#define PREFIX_COPIES 2
#define PACKETS_PER_REPEAT (PREFIX_COPIES + 1)
#define TOTAL_PACKETS (REPEATS * PACKETS_PER_REPEAT)
#define MAX_PACKET 2048

typedef struct {
    int fd;
    uint8_t packets[TOTAL_PACKETS][MAX_PACKET];
    size_t lengths[TOTAL_PACKETS];
    int received;
} receiver;

static void *receive_packets(void *arg) {
    receiver *r = arg;
    for (int i = 0; i < TOTAL_PACKETS; i++) {
        ssize_t n = recv(r->fd, r->packets[i], sizeof r->packets[i], 0);
        if (n <= 0) break;
        r->lengths[i] = (size_t)n;
        r->received++;
    }
    return NULL;
}

int main(void) {
    int fails = 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    struct sockaddr_in addr = {.sin_family = AF_INET};
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(fd);
        return 1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("bind");
        close(fd);
        return 1;
    }
    socklen_t addr_len = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) != 0) {
        perror("getsockname");
        close(fd);
        return 1;
    }

    receiver r = {.fd = fd};
    pthread_t thread;
    if (pthread_create(&thread, NULL, receive_packets, &r) != 0) {
        perror("pthread_create");
        close(fd);
        return 1;
    }

    d2k_quic_allow_local = 1;
    static const uint8_t decoy[] = {0xFA, 0xCE};
    d2k_quic_arm_question question = {
        .addr = "127.0.0.1", .blob = decoy, .blob_len = sizeof decoy,
        .copies = PREFIX_COPIES
    };
    int sent = 0;
    d2k_tally tally = d2k_quic_ask_arm_hook(&question, "fresh.example",
        ntohs(addr.sin_port), 50, 0, &sent);

    (void)pthread_join(thread, NULL);
    close(fd);

    if (r.received != TOTAL_PACKETS || sent != REPEATS || tally.fail != REPEATS) {
        printf("FAIL repeats sent=%d received=%d unanswered=%d\n", sent, r.received,
               tally.fail);
        fails++;
    }

    uint8_t hellos[REPEATS][1024];
    size_t hello_lens[REPEATS] = {0};
    char sni[256];
    for (int attempt = 0; attempt < REPEATS; attempt++) {
        int base = attempt * PACKETS_PER_REPEAT;
        for (int copy = 0; copy < PREFIX_COPIES; copy++) {
            if (r.lengths[base + copy] != sizeof decoy ||
                memcmp(r.packets[base + copy], decoy, sizeof decoy) != 0) {
                printf("FAIL repeat %d lost decoy packet %d\n", attempt, copy);
                fails++;
            }
        }
        int initial = base + PREFIX_COPIES;
        if (d2k_quic_client_hello(r.packets[initial], r.lengths[initial],
                                  hellos[attempt], sizeof hellos[attempt], &hello_lens[attempt]) != 0 ||
            d2k_quic_sni(r.packets[initial], r.lengths[initial], sni, sizeof sni) != 0 ||
            strcmp(sni, "fresh.example") != 0) {
            printf("FAIL repeat %d did not carry a valid fresh.example Initial\n", attempt);
            fails++;
        }
    }
    if (r.received == TOTAL_PACKETS) {
        for (int i = 0; i < REPEATS; i++) {
            for (int j = i + 1; j < REPEATS; j++) {
                if (hello_lens[i] == hello_lens[j] &&
                    memcmp(hellos[i], hellos[j], hello_lens[i]) == 0) {
                    printf("FAIL repeats %d and %d reused the same ClientHello\n", i, j);
                    fails++;
                }
            }
        }
    }

    if (fails) return 1;
    puts("fresh QUIC arm repeats: passed");
    return 0;
}
