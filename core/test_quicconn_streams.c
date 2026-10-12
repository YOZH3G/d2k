/* test_quicconn_streams.c — ПРЕДЕЛ ПОТОКОВ, ОБЪЯВЛЕННЫЙ СЕРВЕРОМ, обязан
 * останавливать нас самих (задача 29).
 *
 * Воспроизведение обрыва по бюджету коробки (d2k_quic_data_stage) открывает
 * по двунаправленному потоку на КАЖДЫЙ запрос: req_sid += 4. В поле 12.10 на
 * это уходило 17–18 запросов, то есть доходило до потока 68 — при полном
 * незнании того, сколько потоков разрешил сервер: свои транспортные параметры
 * d2k_qc объявлял, а его не читал ни разу, и кадр MAX_STREAMS пропускал по
 * длине. Сервер с низким initial_max_streams_bidi обязан закрыть связь кодом
 * STREAM_LIMIT_ERROR (0x04) либо промолчать. Ложным ОБРЫВОМ это не станет
 * (оба исхода уже дают «не измерено»), но ЗАМЕР НА ТАКОМ СЕРВЕРЕ НЕ
 * СОСТОИТСЯ и будет выглядеть нехваткой времени. Дыра в измерении.
 *
 * Стенд на петле: связь d2k_qc с ключами из постоянного секрета (как
 * test_quicconn_fc), «сервер» — вторая такая же связь, посылающая готовые
 * кадры. Живого рукопожатия здесь нет и не нужно: предел приезжает двумя
 * путями — транспортными параметрами в EncryptedExtensions и кадром
 * MAX_STREAMS, — и проверяются ОБА, включая то, что чужой параметр разбор не
 * ломает и что НЕобъявленный предел ничего не ограничивает.
 */
#include "quicconn.c"

#include <assert.h>
#include <fcntl.h>

static int fails;
#define CHECK(x, m) do { if (!(x)) { printf("FAIL %s (строка %d)\n", m, __LINE__); fails++; } \
                         else { printf("ok   %s\n", m); } } while (0)

static void keys(d2k_qc *c) {
    uint8_t secret[32];
    memset(secret, 0x42, sizeof secret);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].tx) == 0);
    assert(d2k_qw_keys_from_secret(c->version, secret, &c->lv[D2K_QW_LEVEL_APP].rx) == 0);
}

/* Связь с прикладными ключами и сокетом на сервер: рукопожатия нет, а всё
   остальное — настоящее. */
static d2k_qc *mk_client(const struct sockaddr_in *srv_addr) {
    d2k_qc *c = calloc(1, sizeof *c);
    assert(c);
    c->fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(c->fd >= 0);
    assert(connect(c->fd, (const struct sockaddr *)srv_addr, sizeof *srv_addr) == 0);
    c->peer_name = -1;
    c->version = D2K_QW_V1;
    c->dcid_len = 8; memset(c->dcid, 0x5a, 8);
    c->scid_len = 8; memset(c->scid, 0x77, 8);
    keys(c);
    return c;
}

/* Кадр MAX_STREAMS: сервер расширяет предел по мере закрытия потоков. */
static void srv_max_streams(d2k_qc *srv, int uni, uint64_t limit) {
    uint8_t fr[16];
    size_t o = 0;
    fr[o++] = (uint8_t)(uni ? FR_MAX_STREAMS_UNI : FR_MAX_STREAMS_BIDI);
    o += d2k_qw_varint_write(fr + o, sizeof fr - o, limit);
    char err[160];
    assert(send_level(srv, D2K_QW_LEVEL_APP, fr, o, 0, err, sizeof err) == 0);
}

/* Клиент разбирает то, что лежит на сокете. Данных потока здесь нет — важно
   только, что кадры сервера прошли через frames_in. */
static void client_pump(d2k_qc *c) {
    char err[200];
    uint8_t buf[2048];
    uint64_t sid = 0;
    (void)d2k_qc_stream_recv(c, &sid, buf, sizeof buf, 30, err, sizeof err);
}

/* Запрос длиной n байт на потоке sid: 0 — ушёл, -1 — отказ с причиной. */
static int ask_n(d2k_qc *c, uint64_t sid, size_t n, char *err, size_t errcap) {
    static uint8_t req[1300];
    assert(n <= sizeof req);
    memset(req, 'x', n);
    err[0] = '\0';
    return d2k_qc_stream_send(c, sid, req, n, 1, err, errcap);
}

static int ask(d2k_qc *c, uint64_t sid, char *err, size_t errcap) {
    return ask_n(c, sid, 5, err, errcap);
}

/* EncryptedExtensions сервера: список расширений, в котором ЧУЖИЕ стоят и до
   нашего, и после. tp — содержимое quic_transport_parameters (0x0039);
   NULL — расширения нет вовсе. */
static size_t ee_build(uint8_t *out, size_t cap, const uint8_t *tp, size_t tp_len) {
    uint8_t x[512];
    size_t o = 0;
    x[o++] = 0x12; x[o++] = 0x34; x[o++] = 0x00; x[o++] = 0x03;   /* чужое до */
    x[o++] = 0xde; x[o++] = 0xad; x[o++] = 0xbe;
    if (tp) {
        x[o++] = 0x00; x[o++] = 0x39;
        x[o++] = (uint8_t)(tp_len >> 8); x[o++] = (uint8_t)tp_len;
        assert(o + tp_len <= sizeof x);
        memcpy(x + o, tp, tp_len); o += tp_len;
    }
    x[o++] = 0x00; x[o++] = 0x10; x[o++] = 0x00; x[o++] = 0x02;   /* чужое после */
    x[o++] = 0x00; x[o++] = 0x01;
    assert(o + 2 <= cap);
    out[0] = (uint8_t)(o >> 8); out[1] = (uint8_t)o;
    memcpy(out + 2, x, o);
    return o + 2;
}

int main(void) {
    char err[200];
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    assert(s >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
    socklen_t len = sizeof a;
    assert(getsockname(s, (struct sockaddr *)&a, &len) == 0);

    d2k_qc *c = mk_client(&a);
    struct sockaddr_in ca;
    socklen_t cl = sizeof ca;
    assert(getsockname(c->fd, (struct sockaddr *)&ca, &cl) == 0);
    assert(connect(s, (struct sockaddr *)&ca, cl) == 0);
    assert(fcntl(s, F_SETFL, O_NONBLOCK) == 0);

    d2k_qc *srv = calloc(1, sizeof *srv);
    assert(srv);
    srv->fd = s;
    srv->version = D2K_QW_V1;
    srv->dcid_len = 8; memset(srv->dcid, 0x77, 8);
    keys(srv);

    /* --- 0. Предел НЕ ОБЪЯВЛЕН: ограничивать нечем ------------------------ */
    CHECK(!c->peer_streams_set[0] && !c->peer_streams_set[1],
          "до слова сервера предел неизвестен");
    CHECK(ask(c, 68, err, sizeof err) == 0,
          "без объявленного предела поток 68 уходит как прежде");

    /* --- 1. Предел из кадра MAX_STREAMS ----------------------------------- */
    srv_max_streams(srv, 0, 3);
    client_pump(c);
    CHECK(c->peer_streams_set[0] && c->peer_streams[0] == 3,
          "кадр MAX_STREAMS 0x12 запомнен (прежде пропускался)");

    for (uint64_t k = 0; k < 3; k++) {
        char m[96];
        snprintf(m, sizeof m, "поток %llu (%llu-й из 3) ушёл",
                 (unsigned long long)(k * 4), (unsigned long long)(k + 1));
        CHECK(ask(c, k * 4, err, sizeof err) == 0, m);
    }
    int rc = ask(c, 12, err, sizeof err);
    printf("     поток 12 (4-й из 3): rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0, "поток 12 (4-й) ОТКАЗАН: сервер разрешил 3");
    CHECK(rc != 0 && strstr(err, "предел потоков сервера") != NULL,
          "причина отказа называет предел потоков СЕРВЕРА, а не сеть");
    CHECK(c->have_want && c->want_stream == 8,
          "отказ не сбросил учёт уже идущего потока 8");

    /* Поле 12.10: воспроизведение по бюджету доходило до потока 68. */
    rc = ask(c, 68, err, sizeof err);
    printf("     поток 68 (18-й из 3): rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0, "поток 68 (18-й, как в поле) ОТКАЗАН: сервер разрешил 3");

    /* --- 2. Сервер расширил предел ---------------------------------------- */
    srv_max_streams(srv, 0, 20);
    client_pump(c);
    CHECK(ask(c, 68, err, sizeof err) == 0, "после MAX_STREAMS 20 поток 68 (18-й) ушёл");
    rc = ask(c, 80, err, sizeof err);
    printf("     поток 80 (21-й из 20): rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0, "поток 80 (21-й) ОТКАЗАН: сервер разрешил 20");

    /* Меньшее значение предел не сужает (RFC 9000 §19.11). */
    srv_max_streams(srv, 0, 2);
    client_pump(c);
    CHECK(ask(c, 68, err, sizeof err) == 0, "MAX_STREAMS 2 после 20 предел не сузил");

    /* --- 3. Однонаправленные потоки — свой счёт (кадр 0x13) --------------- */
    srv_max_streams(srv, 1, 1);
    client_pump(c);
    CHECK(c->peer_streams_set[1] && c->peer_streams[1] == 1, "кадр 0x13 запомнен");
    CHECK(ask(c, 2, err, sizeof err) == 0, "управляющий поток 2 (1-й из 1) ушёл");
    rc = ask(c, 6, err, sizeof err);
    printf("     поток 6 (2-й однонапр. из 1): rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0, "поток 6 (2-й однонаправленный) ОТКАЗАН: сервер разрешил 1");

    /* --- 4. Пределы из транспортных параметров сервера -------------------- */
    uint8_t tp[256], ee[512];
    size_t t = 0;
    t += tp_put_int(tp + t, sizeof tp - t, 0x01, 30000);   /* max_idle_timeout */
    /* ЧУЖОЙ параметр ПЕРЕД пределами: пропуск не по длине съел бы их. */
    t += d2k_qw_varint_write(tp + t, sizeof tp - t, 0x2ab3);
    t += d2k_qw_varint_write(tp + t, sizeof tp - t, 5);
    memset(tp + t, 0xa5, 5); t += 5;
    /* initial_source_connection_id: значение не число и не varint. */
    t += d2k_qw_varint_write(tp + t, sizeof tp - t, 0x0f);
    t += d2k_qw_varint_write(tp + t, sizeof tp - t, 8);
    memset(tp + t, 0x5a, 8); t += 8;
    t += tp_put_int(tp + t, sizeof tp - t, 0x04, 1000);    /* initial_max_data */
    t += tp_put_int(tp + t, sizeof tp - t, 0x06, 500);     /* bidi_remote */
    t += tp_put_int(tp + t, sizeof tp - t, 0x08, 2);       /* streams_bidi */
    t += tp_put_int(tp + t, sizeof tp - t, 0x09, 1);       /* streams_uni */
    size_t ee_len = ee_build(ee, sizeof ee, tp, t);

    d2k_qc *c2 = mk_client(&a);
    tp_server_ee(c2, ee, ee_len);
    printf("     разобрано: потоки дву %llu уста %d, одно %llu, данные связи %llu, потока %llu\n",
           (unsigned long long)c2->peer_streams[0], c2->peer_streams_set[0],
           (unsigned long long)c2->peer_streams[1],
           (unsigned long long)c2->peer_max_data,
           (unsigned long long)c2->peer_sdata[0]);
    CHECK(c2->peer_streams_set[0] && c2->peer_streams[0] == 2,
          "initial_max_streams_bidi (0x08) разобран через чужой параметр");
    CHECK(c2->peer_streams_set[1] && c2->peer_streams[1] == 1,
          "initial_max_streams_uni (0x09) разобран");
    CHECK(c2->peer_max_data_set && c2->peer_max_data == 1000,
          "initial_max_data (0x04) разобран");
    CHECK(c2->peer_sdata_set[0] && c2->peer_sdata[0] == 500,
          "initial_max_stream_data_bidi_remote (0x06) разобран");
    /* Причина печатается при отказе НЕ для красоты. Отправка идёт настоящей
       датаграммой в локальный сокет (c->fd), и send() под нагрузкой вправе
       отказать — например ENOBUFS, когда приёмник не разобран. Такой отказ
       неотличим от отказа по пределу, если причину не показать: прогон
       12.10.2026 под санитайзером упал здесь один раз и не повторился. */
    {
        int r0 = ask(c2, 0, err, sizeof err);
        if (r0 != 0) { printf("     поток 0 не ушёл: %s\n", err[0] ? err : "(без причины)"); }
        int r4 = ask(c2, 4, err, sizeof err);
        if (r4 != 0) { printf("     поток 4 не ушёл: %s\n", err[0] ? err : "(без причины)"); }
        CHECK(r0 == 0 && r4 == 0, "два потока из объявленных двух ушли");
    }
    rc = ask(c2, 8, err, sizeof err);
    printf("     поток 8 (3-й из 2 по параметрам): rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0, "третий поток ОТКАЗАН: в параметрах их два");
    CHECK(rc != 0 && strstr(err, "предел потоков сервера") != NULL,
          "причина из параметров — та же, про предел сервера");

    /* --- 5. Пределы данных, объявленные сервером -------------------------- */
    rc = ask_n(c2, 0, 600, err, sizeof err);
    printf("     600 байт в поток при пределе 500: rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0 && strstr(err, "предел данных потока сервера") != NULL,
          "посылка больше initial_max_stream_data отказана с внятной причиной");

    size_t t2 = 0;
    t2 += tp_put_int(tp + t2, sizeof tp - t2, 0x04, 1000);     /* данные связи */
    t2 += tp_put_int(tp + t2, sizeof tp - t2, 0x06, 100000);   /* данные потока */
    t2 += tp_put_int(tp + t2, sizeof tp - t2, 0x08, 50);
    ee_len = ee_build(ee, sizeof ee, tp, t2);
    d2k_qc *c3 = mk_client(&a);
    tp_server_ee(c3, ee, ee_len);
    CHECK(ask_n(c3, 0, 900, err, sizeof err) == 0, "900 байт при пределе связи 1000 ушли");
    rc = ask_n(c3, 4, 1200, err, sizeof err);
    printf("     1200 байт при пределе связи 1000: rc=%d err=%s\n", rc, err[0] ? err : "(пусто)");
    CHECK(rc != 0 && strstr(err, "предел данных связи сервера") != NULL,
          "посылка больше initial_max_data отказана с внятной причиной");

    /* --- 6. Параметров нет вовсе: число за сервер не выдумывается --------- */
    ee_len = ee_build(ee, sizeof ee, NULL, 0);
    d2k_qc *c4 = mk_client(&a);
    tp_server_ee(c4, ee, ee_len);
    CHECK(!c4->peer_streams_set[0] && !c4->peer_streams_set[1] &&
          !c4->peer_max_data_set && !c4->peer_sdata_set[0],
          "без расширения 0x0039 ни один предел не придуман");
    CHECK(ask(c4, 68, err, sizeof err) == 0,
          "без параметров поведение прежнее: поток 68 уходит");

    d2k_qc_close(c);
    d2k_qc_close(c2);
    d2k_qc_close(c3);
    d2k_qc_close(c4);
    free(srv);
    close(s);
    if (!fails) puts("QUIC: предел потоков и данных сервера соблюдается");
    return fails != 0;
}
