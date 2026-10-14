/* whitets.c — почему приём white-hello-ts срабатывает 2 раза из 3.
 *
 * Поле 14.10.2026, fost.club (172.67.220.65): вопрос «ECH-приветствие под
 * меткой» к одному адресу — 3/3, 0/1, 2/3, 1/2, с любой приманкой. Стенд шлёт
 * тот же приём тем же зондом (d2k_raw_probe_poison_family, общий с датапатом
 * plan_apply) N раз подряд и печатает исход каждой попытки с меткой времени,
 * чтобы сверить с tcpdump на роутере. Только для опытов: в сборку не входит.
 *
 *   whitets <ip> <имя> <белое-имя> <попыток> <пауза-мс> [копий] [ts 0|1] [метка]
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
    clock_gettime(CLOCK_REALTIME, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "whitets <ip> <имя> <белое-имя> <попыток> <пауза-мс> [копий] [ts] [метка] [ttl] [badsum]\n");
        return 2;
    }
    uint8_t ip[4];
    if (inet_pton(AF_INET, argv[1], ip) != 1) { fprintf(stderr, "адрес\n"); return 2; }
    int n = atoi(argv[4]), pause = atoi(argv[5]);
    int copies = argc > 6 ? atoi(argv[6]) : 8;
    int ts = argc > 7 ? atoi(argv[7]) : 1;
    uint32_t mark = argc > 8 ? (uint32_t)strtoul(argv[8], NULL, 0) : 0x2f;
    int ttl = argc > 9 ? atoi(argv[9]) : 0;
    int badsum = argc > 10 ? atoi(argv[10]) : 0;
    d2k_trigger tr;
    char err[200];
    memset(&tr, 0, sizeof tr);
    if (d2k_trigger_tls(argv[2], 0, &tr, err, sizeof err) != 0) { fprintf(stderr, "%s\n", err); return 1; }
    static uint8_t white[2048];
    size_t wl = 0;
    if (d2k_white_decoy_hello(argv[3], white, sizeof white, &wl) != 0) { fprintf(stderr, "белое\n"); return 1; }
    d2k_poison p;
    memset(&p, 0, sizeof p);
    snprintf(p.name, sizeof p.name, "white-hello-ts");
    p.tcp_ts = ts;
    p.decoy_hello = 1;
    p.decoy = white;
    p.decoy_len = wl;
    p.repeats = copies;
    p.split_pos = 2;
    p.ttl = ttl;
    p.badsum = badsum;
    d2k_detect_stop stop;
    memset(&stop, 0, sizeof stop);
    int pass = 0;
    for (int i = 0; i < n; i++) {
        long long t0 = now_ms();
        err[0] = 0;
        int rc = d2k_raw_probe_poison_family(ip, 4, 443, &tr, &p, 6000, mark, &stop, err, sizeof err);
        long long t1 = now_ms();
        if (rc > 0) pass++;
        time_t sec = (time_t)(t0 / 1000);
        struct tm tm;
        localtime_r(&sec, &tm);
        printf("%02d:%02d:%02d.%03lld попытка %d: %s за %lld мс %s\n", tm.tm_hour, tm.tm_min, tm.tm_sec,
               t0 % 1000, i + 1, rc > 0 ? "ПРОШЛО" : rc == 0 ? "нет" : "ошибка", t1 - t0, err);
        fflush(stdout);
        if (pause > 0 && i + 1 < n) {
            struct timespec d = { pause / 1000, (long)(pause % 1000) * 1000000L };
            nanosleep(&d, NULL);
        }
    }
    printf("итог: %d из %d (белое %s, копий %d, ts %d, ttl %d, badsum %d)\n", pass, n, argv[3], copies, ts, ttl, badsum);
    return 0;
}
