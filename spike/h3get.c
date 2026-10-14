/* h3get.c — задача 50: доходит ли у НАШЕГО клиента QUIC/H3 второй и третий
 * поток. Только для опытов: в сборку d2k не входит.
 *
 * Дефект A звучал так: рукопожатие 3/3, первый ответ пришёл, а следующий
 * поток H3 встал. Развести «наш клиент на втором потоке» и «коробка» можно
 * только одним способом — тем же клиентом там, где коробки нет (VPS). Если и
 * там поток встаёт, ошибка наша; если там всё доходит, а с линии нет, — это
 * линия.
 *
 * Запросы идут ПО ОЧЕРЕДИ, как у зонда с бюджетом данных: поток 0, 4, 8…,
 * каждый ответ читается до FIN без дыр (d2k_qc_app_progress) или до паузы.
 *
 *   h3get <ip> <имя> <путь> [повторов]
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_h3.h"
#include "d2k_quicconn.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static long long ms_now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "использование: h3get <ip> <имя> <путь> [повторов]\n");
        return 2;
    }
    int repeats = argc > 4 ? atoi(argv[4]) : 3;
    d2k_qc_opts o;
    memset(&o, 0, sizeof o);
    o.ip = argv[1]; o.sni = argv[2]; o.port = 443; o.alpn = "h3"; o.deadline_ms = 8000;

    d2k_qc *c = NULL;
    char err[256] = "";
    long long t0 = ms_now();
    if (d2k_qc_connect(&o, &c, err, sizeof err) != 0) {
        printf("рукопожатие НЕ завершилось: %s\n", err);
        return 1;
    }
    printf("рукопожатие за %lld мс, имя в сертификате %d\n", ms_now() - t0, d2k_qc_peer_name(c));

    uint8_t ctl[16];
    size_t cn = d2k_h3_control(ctl, sizeof ctl);
    uint8_t qe[1] = { 0x02 }, qd[1] = { 0x03 };
    if (d2k_qc_stream_send(c, 2, ctl, cn, 0, err, sizeof err) != 0) {
        printf("управляющий поток не ушёл: %s\n", err); d2k_qc_close(c); return 1;
    }
    (void)d2k_qc_stream_send(c, 6, qe, 1, 0, err, sizeof err);
    (void)d2k_qc_stream_send(c, 10, qd, 1, 0, err, sizeof err);
    { uint64_t sid; uint8_t tmp[2048]; (void)d2k_qc_stream_recv(c, &sid, tmp, sizeof tmp, 400, err, sizeof err); }

    int bad = 0;
    for (int k = 0; k < repeats; k++) {
        uint64_t sid = (uint64_t)k * 4;
        uint8_t req[1024];
        size_t rn = d2k_h3_request(argv[2], argv[3], req, sizeof req);
        uint64_t tx0, rx0; d2k_qc_dgrams(c, &tx0, &rx0);
        long long s0 = ms_now();
        if (rn == 0 || d2k_qc_stream_send(c, sid, req, rn, 1, err, sizeof err) != 0) {
            printf("запрос %d (поток %llu) не ушёл: %s\n", k + 1, (unsigned long long)sid, err);
            bad = 1; break;
        }
        uint8_t head[8192]; size_t hn = 0; int status = 0;
        long long last = ms_now();
        uint64_t bytes = 0; int complete = 0, closed = 0;
        while (ms_now() - last < 3000 && ms_now() - s0 < 15000) {
            uint64_t from = 0; uint8_t buf[16384];
            long n = d2k_qc_stream_recv(c, &from, buf, sizeof buf, 200, err, sizeof err);
            if (n < 0) { closed = 1; break; }
            if (n > 0) {
                last = ms_now();
                if (hn < sizeof head) {
                    size_t take = (size_t)n < sizeof head - hn ? (size_t)n : sizeof head - hn;
                    memcpy(head + hn, buf, take); hn += take;
                }
                if (!status && hn) { (void)d2k_h3_status(head, hn, &status); }
            }
            d2k_qc_app_progress(c, &bytes, &complete);
            if (complete) { break; }
        }
        uint64_t tx1, rx1; d2k_qc_dgrams(c, &tx1, &rx1);
        printf("запрос %d (поток %llu): статус %d, принято %llu байт, %s, датаграмм +%llu/+%llu, %lld мс%s\n",
               k + 1, (unsigned long long)sid, status, (unsigned long long)bytes,
               complete ? "ОТВЕТ ЦЕЛИКОМ" : "НЕ ЦЕЛИКОМ",
               (unsigned long long)(tx1 - tx0), (unsigned long long)(rx1 - rx0),
               ms_now() - s0, closed ? " — соединение закрыто" : "");
        if (!complete) { bad = 1; }
        if (closed) { break; }
    }
    d2k_qc_close(c);
    return bad;
}
