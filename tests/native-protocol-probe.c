/* Exercise production verifiers against an independent native IPv6 server. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d2k_verify.h"
#include "d2k_compose_internal.h"

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: native-protocol-probe 12|13|quic ipv6 port name\n");
        return 2;
    }
    struct in6_addr target;
    long port = strtol(argv[3], NULL, 10);
    if (inet_pton(AF_INET6, argv[2], &target) != 1 || port < 1 || port > 65535)
        return 2;
    d2k_ver_result result;
    int fd = -1;
    uint16_t reserved = 0;
    int bind_result = !strcmp(argv[1], "quic") ?
        d2k_props_bind_udp_family(6, &fd, &reserved) :
        d2k_props_bind_family(6, &fd, &reserved);
    if (bind_result) return 1;
    if (!strcmp(argv[1], "12"))
        result = d2k_verify_probe12_on(fd, argv[2], (uint16_t)port, argv[4], 5000, 0);
    else if (!strcmp(argv[1], "13"))
        result = d2k_verify_probe_on(fd, argv[2], (uint16_t)port, argv[4], 5000, 0);
    else if (!strcmp(argv[1], "quic"))
        result = d2k_verify_probe_quic_on(fd, argv[2], (uint16_t)port, argv[4], 5000, 0);
    else return 2;
    char local[INET6_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET6, result.local_addr, local, sizeof local);
    printf("%s IPv%u local=[%s]:%u level=%d status=%d name=%d: %s\n",
           argv[1], result.family, local, result.local_port,
           result.level, result.status, result.name_ok, result.reason);
    int ok = result.family == 6 && result.local_port == ntohs(reserved) && reserved != 0 &&
             result.level == D2K_VER_APPLICATION && result.status == 200 && result.name_ok == 1;
    d2k_verify_close(&result);
    return ok ? 0 : 1;
}
