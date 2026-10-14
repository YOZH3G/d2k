/* quicv2.c — задача 57: что вообще значит ответ на вопрос «версия2».
 *
 * Вопрос «версия2» шлёт тот же Initial во второй версии QUIC (RFC 9369), и
 * ответом по критерию донора считается и Version Negotiation. У fost.club
 * (Cloudflare) вопрос дал 0/3 — тишину. Это либо коробка режет по имени и
 * v2, либо сервер на неизвестную ему версию молчит вовсе — и тогда «0/3» на
 * его адресах выдаёт отсутствие ответа за «нет». Развести можно только
 * контролем: тот же Initial v2 к тому же адресу с именем, которое коробка
 * не трогает. Только для опытов: в сборку d2k не входит.
 *
 *   quicv2 <ip> <имя> [повторов]
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_quichello.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Что пришло в ответ — только по открытому заголовку, без расшифровки. */
static const char *kind(const uint8_t *b, size_t n, char *buf, size_t cap) {
    if (n < 5) { snprintf(buf, cap, "обрывок %zu байт", n); return buf; }
    if (!(b[0] & 0x80)) { snprintf(buf, cap, "короткий заголовок, %zu байт", n); return buf; }
    uint32_t v = (uint32_t)b[1] << 24 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 8 | b[4];
    if (v == 0) { snprintf(buf, cap, "Version Negotiation, %zu байт", n); return buf; }
    snprintf(buf, cap, "длинный заголовок версии 0x%08x, %zu байт", v, n);
    return buf;
}

static void ask(const char *ip, const uint8_t *pkt, size_t len, const char *label, int tries) {
    int answered = 0;
    for (int k = 0; k < tries; k++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons(443); inet_pton(AF_INET, ip, &a.sin_addr);
        if (fd < 0 || sendto(fd, pkt, len, 0, (struct sockaddr *)&a, sizeof a) != (ssize_t)len) {
            printf("  %s, опыт %d: не ушло\n", label, k + 1);
            if (fd >= 0) close(fd);
            continue;
        }
        struct pollfd p = { fd, POLLIN, 0 };
        char what[96] = "тишина 1,5 с";
        if (poll(&p, 1, 1500) > 0) {
            uint8_t b[2048];
            ssize_t n = recv(fd, b, sizeof b, 0);
            if (n > 0) { kind(b, (size_t)n, what, sizeof what); answered++; }
        }
        printf("  %s, опыт %d: %s\n", label, k + 1, what);
        close(fd);
        poll(NULL, 0, 300);
    }
    printf("  %s: ответ %d из %d\n", label, answered, tries);
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "использование: quicv2 <ip> <имя> [повторов]\n"); return 2; }
    int tries = argc > 3 ? atoi(argv[3]) : 3;
    uint8_t v1[1500], v2[1500];
    size_t n1 = 0, n2 = 0;
    if (d2k_quic_probe_initial(argv[2], v1, sizeof v1, &n1) != 0) {
        fprintf(stderr, "Initial v1 не собрался\n"); return 1;
    }
    if (d2k_quic_hello_ask(v1, n1, D2K_QASK_VERSION2, argv[2], v2, sizeof v2, &n2) != 0) {
        fprintf(stderr, "Initial v2 не собрался\n"); return 1;
    }
    /* Смазочная версия (RFC 9000 §15, вида 0x?a?a?a?a): сервер, получивший
       Initial неизвестной версии длиной от 1200 байт, обязан ответить Version
       Negotiation (§6). Ответил на смазку и молчит на v2 — v2 съел не сервер. */
    uint8_t gr[1500];
    memcpy(gr, v1, n1);
    gr[1] = 0x1a; gr[2] = 0x2a; gr[3] = 0x3a; gr[4] = 0x4a;
    printf("%s через %s: Initial v1 %zu байт, v2 %zu байт\n", argv[2], argv[1], n1, n2);
    ask(argv[1], v1, n1, "v1", tries);
    ask(argv[1], v2, n2, "v2", tries);
    ask(argv[1], gr, n1, "смазка 0x1a2a3a4a", tries);
    return 0;
}
