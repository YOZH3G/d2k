/* RX объёмный диагноз — чистые ответы измерителя, без сети. */
#include <stdio.h>
#include <string.h>

#include "d2k_volume.h"

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("ПРОВАЛ: %s\n", msg); fails++; } \
} while (0)

static d2k_ver_result identity_cut(uint64_t bytes, uint64_t expected,
                                   int has_length, int chunked) {
    d2k_ver_result r;
    memset(&r, 0, sizeof r);
    r.status = 200;
    r.body_bytes = bytes;
    r.body_expected = expected;
    r.body_has_length = has_length;
    r.body_chunked = chunked;
    r.body_framing_valid = 1;
    r.body_complete = 0;
    return r;
}

int main(void) {
    d2k_ver_result a = identity_cut(23900, 96460, 1, 0);
    d2k_ver_result b = identity_cut(24020, 98112, 1, 0); /* динамический CL */
    d2k_ver_result gz = identity_cut(18000, 18000, 1, 0);
    gz.body_complete = 1;
    gz.body_encoding = 1;
    d2k_vol_result out;
    memset(&out, 0, sizeof out);

    CHECK(d2k_volume_rx_evidence(&a, &b, &gz, &out),
          "повторяемый Content-Length RX-обрыв с полным gzip не распознан");
    CHECK(out.rx_cut && out.rx_at_kb == 23 && out.rx_expected_kb == 94 &&
          out.rx_compressed_complete,
          "RX-примета не содержит измеренный размер и завершённый контроль");

    a = identity_cut(23900, 0, 0, 1);
    b = identity_cut(24020, 0, 0, 1);
    memset(&out, 0, sizeof out);
    CHECK(d2k_volume_rx_evidence(&a, &b, &gz, &out),
          "повторяемый chunked RX-обрыв не распознан без Content-Length");
    CHECK(out.rx_cut && out.rx_expected_kb == 0 && strstr(out.reason, "chunked") != NULL,
          "chunked-обрыв выдан за известный полный размер");

    a = identity_cut(12000, 50000, 1, 0);
    b = identity_cut(20000, 50000, 1, 0);
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "неповторяемые объёмы ошибочно названы блокировкой");

    a = identity_cut(23900, 50000, 1, 0);
    b = identity_cut(24020, 50000, 1, 0);
    gz.body_encoding = 0;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "полный, но фактически несжатый контроль принят за gzip");

    gz.body_encoding = 1;
    gz.body_complete = 0;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "оборванный gzip-контроль ошибочно подтвердил объёмный диагноз");

    gz.body_complete = 1;
    b.body_chunked = 1;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "разные HTTP framing виды ошибочно склеены в одну примету");

    b = a;
    a.body_chunked = 1;
    a.body_has_length = 1;
    b.body_chunked = 1;
    b.body_has_length = 1;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "противоречивые Content-Length и chunked приняты за обрыв по объёму");

    a = identity_cut(23900, 50000, 1, 0);
    b = identity_cut(24020, 50000, 1, 0);
    gz = identity_cut(0, 0, 0, 0);
    gz.body_complete = 1;
    gz.body_encoding = 1;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "пустой gzip-ответ принят за успешный контроль доставки");

    a = identity_cut(11000, 40000, 1, 0);
    b = identity_cut(11020, 40000, 1, 0);
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "слишком ранний/малый обрыв принят за сигнатуру крупного ответа");

    if (fails) {
        printf("test_volume: %d failure(s)\n", fails);
        return 1;
    }
    puts("test_volume: OK");
    return 0;
}
