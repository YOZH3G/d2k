/* pathprobe.c — какой приём берёт «плохой» маршрут к fost.club.
 *
 * Поле 14.10.2026: провайдер разводит соединения к 172.67.220.65 по разным
 * маршрутам (TTL SYN-ACK 53–54 против 55–57); white-hello-ts проходит на
 * вторых всегда и не проходит на первых никогда, с VPS — 20/20. Стенд гоняет
 * каждый приём каталога дерева (d2k_poisons) и white-hello-ts по кругу, по
 * одному соединению на попытку, и печатает строку на попытку. Маршрут
 * попытки берётся из tcpdump по порядку соединений. Только для опытов.
 *
 *   pathprobe <ip> <имя> <белое-имя> <кругов> <тайм-аут-мс> [контроль] [метка]
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_detect.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int d2k_white_decoy_hello(const char *name, uint8_t *out, size_t cap, size_t *len);

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "pathprobe <ip> <имя> <белое-имя> <кругов> <тайм-аут-мс> [контроль] [метка]\n");
        return 2;
    }
    uint8_t ip[4];
    if (inet_pton(AF_INET, argv[1], ip) != 1) { fprintf(stderr, "адрес\n"); return 2; }
    int rounds = atoi(argv[4]), tmo = atoi(argv[5]);
    const char *ctl_name = argc > 6 ? argv[6] : "disk.rzd.ru";
    uint32_t mark = argc > 7 ? (uint32_t)strtoul(argv[7], NULL, 0) : 0x2f;
    char err[200];
    static d2k_trigger tr, ctl;
    if (d2k_trigger_tls(argv[2], 0, &tr, err, sizeof err) ||
        d2k_trigger_tls(ctl_name, 0, &ctl, err, sizeof err)) { fprintf(stderr, "%s\n", err); return 1; }
    static uint8_t white[2048];
    size_t wl = 0;
    if (d2k_white_decoy_hello(argv[3], white, sizeof white, &wl)) { fprintf(stderr, "белое\n"); return 1; }

    int n = 0;
    const d2k_poison *cat = d2k_poisons(&n);
    static d2k_poison list[160];
    int k = 0;
    d2k_poison w;
    memset(&w, 0, sizeof w);
    snprintf(w.name, sizeof w.name, "white-hello-ts");
    w.tcp_ts = 1; w.decoy_hello = 1; w.decoy = white; w.decoy_len = wl;
    w.repeats = 8; w.split_pos = 2;
    list[k++] = w;
    for (int i = 0; i < n && k < 160; i++) {
        d2k_poison p = cat[i];
        if (!d2k_poison_supports_family(&p, 4)) continue;
        if (p.decoy_hello) {
            p.decoy = ctl.payload; p.decoy_len = ctl.len;
            if (p.seqovl_exact) p.seqovl = (int)ctl.len;
        }
        list[k++] = p;
    }
    d2k_detect_stop stop;
    memset(&stop, 0, sizeof stop);
    int idx = 0;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < k; i++) {
            long long t0 = now_ms();
            err[0] = 0;
            int rc = d2k_raw_probe_poison_family(ip, 4, 443, &tr, &list[i], tmo, mark, &stop, err, sizeof err);
            printf("%d\t%s\t%s\t%lld\t%s\n", ++idx, list[i].name,
                   rc > 0 ? "ПРОШЛО" : rc == 0 ? "нет" : "ошибка", now_ms() - t0, err);
            fflush(stdout);
        }
    }
    return 0;
}
