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

    CHECK(out.rx_cut_packets == 0,
          "бюджет коробки выдуман без счёта пакетов (задача 55)");
    /* Задача 55: на обрыве identity замер видит и ПАКЕТЫ — это бюджет
       коробки (поле 04.10: 25–26 пакетов с данными обеих сторон). */
    a.data_packets = 26; b.data_packets = 25;
    memset(&out, 0, sizeof out);
    CHECK(d2k_volume_rx_evidence(&a, &b, &gz, &out) && out.rx_cut_packets == 25,
          "пакеты на обрыве identity не записаны бюджетом коробки");
    a.data_packets = 0; b.data_packets = 27;
    memset(&out, 0, sizeof out);
    CHECK(d2k_volume_rx_evidence(&a, &b, &gz, &out) && out.rx_cut_packets == 27,
          "бюджет не взят из единственного посчитанного обрыва");

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

    /* ПОЛЕ 04.10, rua.gr, позднее закрытие (08:06:28): «RX identity
       22229/22280; gzip HTTP 200, тело 20817, complete=0, encoding=1» —
       и отдых на 10 минут. Коробка режет поток по ~25 ПАКЕТАМ с данными
       (task-55-facts §1.2: 25–27 в 18/18 потоках), а не по байтам, поэтому
       gzip-контроль, которому самому нужно больше бюджета, обрывается тоже.
       Обрыв identity и gzip на одном бюджете пакетов — примета коробки. */
    a = identity_cut(22229, 219136, 1, 0);
    b = identity_cut(22280, 219136, 1, 0);
    gz = identity_cut(20817, 0, 0, 1);
    gz.body_encoding = 1;
    a.data_packets = 26; b.data_packets = 26; gz.data_packets = 25;
    memset(&out, 0, sizeof out);
    CHECK(d2k_volume_rx_evidence(&a, &b, &gz, &out),
          "rua.gr: identity и gzip оборваны на одном бюджете пакетов — примета не принята");
    CHECK(out.rx_cut && out.rx_cut_packets == 25 && !out.rx_compressed_complete &&
          out.rx_at_kb == 21 && strstr(out.reason, "пакет") != NULL,
          "rua.gr: пакетный бюджет коробки не записан или gzip назван завершённым");
    gz.data_packets = 0;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "без счёта пакетов gzip оборванный контроль принят (старое ядро — прежнее правило)");
    gz.data_packets = 25; a.data_packets = 0; b.data_packets = 0;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "без счёта пакетов identity оборванный gzip принят");
    a.data_packets = 26; b.data_packets = 26; gz.data_packets = 60;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "gzip оборван на другом числе пакетов — не тот же бюджет, а принят");
    a.data_packets = 26; b.data_packets = 40; gz.data_packets = 26;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "identity оборваны на разном числе пакетов, а бюджет принят");
    b.data_packets = 26; gz.body_encoding = 0;
    memset(&out, 0, sizeof out);
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out) && !out.rx_cut,
          "несжатый «контроль» принят за пакетную примету");

    /* A complete TLS handshake can be followed by 14 KiB of an unfinished
       encrypted record: HTTP status/body remain zero, not the RX progress.
       Two such cuts need a genuinely shorter, complete gzip control. */
    a = (d2k_ver_result){0};
    a.level = D2K_VER_HANDSHAKE; a.name_ok = 1; a.negotiated_tls = 0x0304;
    a.rx_tls_wire_bytes = 14005; a.rx_tls_record_missing = 2384;
    b = a; b.rx_tls_wire_bytes = 14105; b.rx_tls_record_missing = 2284;
    gz = identity_cut(4000, 4000, 1, 0);
    gz.level = D2K_VER_APPLICATION; gz.name_ok = 1; gz.negotiated_tls = 0x0304;
    gz.body_complete = 1; gz.body_encoding = 1; gz.rx_tls_wire_bytes = 4500;
    CHECK(d2k_volume_rx_partial(&a), "partial TLS ciphertext lost before HTTP headers");
    memset(&out, 0, sizeof out);
    CHECK(d2k_volume_rx_evidence(&a, &b, &gz, &out) && out.rx_cut &&
          out.rx_at_kb == 13 && out.rx_wire_basis && strstr(out.reason, "TLS"),
          "repeat incomplete TLS record + shorter full gzip not recognized");
    b.negotiated_tls = 0x0303;
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out), "TLS versions mixed in wire evidence");
    b.negotiated_tls = a.negotiated_tls;
    b.rx_tls_record_missing = 0;
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out),
          "full bad-tag record mistaken for a wire cut");
    b = a; b.rx_tls_wire_bytes = 24005;
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out), "different wire cuts merged");
    b = a; gz.rx_tls_wire_bytes = 15000;
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out), "larger control proves byte cutoff");
    gz.rx_tls_wire_bytes = 4500; gz.body_complete = 0;
    CHECK(!d2k_volume_rx_evidence(&a, &b, &gz, &out), "incomplete opaque control accepted");
    gz.body_complete = 1; a.level = D2K_VER_TRANSPORT;
    CHECK(!d2k_volume_rx_partial(&a) && !d2k_volume_rx_evidence(&a, &b, &gz, &out),
          "handshake failure counted as application RX cut");
    a.level = D2K_VER_HANDSHAKE; a.local_limit = 1;
    CHECK(!d2k_volume_rx_partial(&a), "local limit counted as path evidence");
    a.local_limit = 0; a.rx_tls_wire_bytes = 1000;
    CHECK(!d2k_volume_rx_partial(&a), "small partial record counted as volume cut");

    if (fails) {
        printf("test_volume: %d failure(s)\n", fails);
        return 1;
    }
    puts("test_volume: OK");
    return 0;
}
