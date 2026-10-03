/* test_ctq.c — запрос счётчиков conntrack по кортежу (d2k_ctq.h).
 *
 * 1. Запрос CT_GET собран по формату ядра (байты сверены с тем, что принял
 *    и на что ответил ctnetlink роутера KN-1811 04.10.2026).
 * 2. Ответ ядра с этого же роутера разбирается: прямой 14, обратный 7.
 * 3. Ошибка ядра (записи нет), чужой seq, ответ без счётчиков — «не знаем».
 * 4. ЦИКЛ ОЧЕРЕДИ НЕ ЖДЁТ: на сокете, который не отвечает вовсе, запрос
 *    возвращается сразу (fail open), а устаревший чужой ответ не путается со
 *    своим. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "d2k_ctq.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s\n", m); fails++; } } while (0)

static size_t unhex(const char *h, uint8_t *o, size_t cap) {
    size_t n = 0;
    while (h[0] && h[1] && n < cap) {
        unsigned v; sscanf(h, "%2x", &v); o[n++] = (uint8_t)v; h += 2;
    }
    return n;
}

static double now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int main(void) {
    d2k_ct_tuple t;
    memset(&t, 0, sizeof t);
    t.family = 4; t.proto = 17;
    inet_pton(AF_INET, "192.168.1.67", t.src);
    inet_pton(AF_INET, "17.248.214.12", t.dst);
    t.sport_be[0] = 0xe6; t.sport_be[1] = 0x8e;   /* 59022 */
    t.dport_be[0] = 0x01; t.dport_be[1] = 0xbb;   /* 443 */

    /* 1. Запрос. */
    uint8_t req[128], want[128];
    size_t n = d2k_ct_get_req(req, sizeof req, 7, &t);
    size_t wn = unhex("48000000" "0101" "0100" "07000000" "00000000"  /* nlmsghdr */
                      "02000000"                                       /* nfgenmsg AF_INET */
                      "34000180"                                       /* CTA_TUPLE_ORIG */
                      "14000180" "08000100c0a80143" "0800020011f8d60c" /* CTA_TUPLE_IP */
                      "1c000280" "0500010011000000"                    /* CTA_TUPLE_PROTO, udp */
                      "06000200e68e0000" "0600030001bb0000",           /* ports */
                      want, sizeof want);
    CHECK(n == 72 && n == wn && memcmp(req, want, n) == 0,
          "запрос CT_GET собран не так, как его принимает ядро");
    CHECK(d2k_ct_get_req(req, 40, 7, &t) == 0, "запрос в маленький буфер собрался");

    /* 2. Ответ ядра роутера (обрезан до счётчиков и статуса). */
    uint8_t rsp[400];
    size_t rn = unhex(
        "440100000001020007000000e966000002000000"
        "340001801400018008000100c0a801430800020011f8d60c1c000280050001001100000006000200e68e000006000300" "01bb0000"
        "340002801400018008000100" "11f8d60c0800020058575d0b1c00028005000100110000000600020001bb000006000300e68e0000"
        "08000300" "0020019e" "08000700" "00000013"
        "1c0009800c00010000000000000000" "0e0c0002000000000000001fd6"
        "1c000a800c00010000000000000000" "070c00020000000000000017f9", rsp, sizeof rsp);
    /* Длина сообщения — по собранному. */
    rsp[0] = (uint8_t)rn; rsp[1] = (uint8_t)(rn >> 8);
    uint64_t o = 0, r = 0;
    CHECK(d2k_ct_counters_parse(rsp, rn, 7, &o, &r) == 0 && o == 14 && r == 7,
          "ответ ядра со счётчиками не разобран (ждали 14/7)");
    CHECK(d2k_ct_counters_parse(rsp, rn, 8, &o, &r) == -1, "ответ на чужой запрос принят");
    /* Без счётчиков (accounting выключен) — не знаем. */
    {
        uint8_t no[64];
        memcpy(no, rsp, 20);
        no[0] = 20; no[1] = 0;
        CHECK(d2k_ct_counters_parse(no, 20, 7, &o, &r) == -1, "запись без счётчиков дала числа");
    }
    /* 3. Ошибка ядра: записи нет (-ENOENT). */
    {
        uint8_t er[36];
        memset(er, 0, sizeof er);
        er[0] = 36; er[4] = 2; /* NLMSG_ERROR */
        er[8] = 9;             /* seq */
        int32_t e = -2;
        memcpy(er + 16, &e, 4);
        CHECK(d2k_ct_counters_parse(er, 36, 9, &o, &r) == 1, "ошибка ядра не распознана");
    }

    /* 4. Неотвечающий сокет: возврат сразу, без ожидания. */
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair");
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
    double a = now_ms();
    for (int i = 0; i < 100; i++) {
        CHECK(d2k_ct_query_fd(sv[0], (uint32_t)(100 + i), &t, &o, &r) == -1,
              "молчащий сокет дал счётчики");
        char drain[256];
        while (recv(sv[1], drain, sizeof drain, MSG_DONTWAIT) > 0) { }
    }
    CHECK(now_ms() - a < 50.0, "сто запросов в молчащий сокет заняли больше 50 мс — цикл ждёт");
    /* Устаревший чужой ответ лежит в сокете, свой следом: берётся свой. */
    {
        uint8_t stale[400];
        memcpy(stale, rsp, rn);
        stale[8] = 0x55;                        /* чужой seq */
        CHECK(send(sv[1], stale, rn, 0) == (ssize_t)rn, "stale send");
        uint8_t mine[400];
        memcpy(mine, rsp, rn);
        mine[8] = 200; mine[9] = mine[10] = mine[11] = 0;
        CHECK(send(sv[1], mine, rn, 0) == (ssize_t)rn, "mine send");
        o = r = 0;
        CHECK(d2k_ct_query_fd(sv[0], 200, &t, &o, &r) == 0 && o == 14 && r == 7,
              "свой ответ за устаревшим чужим не найден");
    }
    close(sv[0]); close(sv[1]);
    CHECK(d2k_ct_query_fd(-1, 1, &t, &o, &r) == -1, "запрос без сокета");

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("ctnetlink по кортежу: все проверки прошли\n");
    return 0;
}
