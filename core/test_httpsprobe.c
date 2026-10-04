/* test_httpsprobe.c — HTTPS имени для перевода вставки на https (задача 51). */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>

#include "d2k_httpsprobe.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int gate_closed, calls;
static d2k_https_state answer = D2K_HTTPS_SERVED;
static uint8_t seen_family, seen_addr[16];
static char seen_host[256];
static uint32_t seen_mark;

static d2k_https_state fake(uint8_t family, const uint8_t *addr, const char *host,
                            uint32_t mark, char *why, size_t cap) {
    pthread_mutex_lock(&mu);
    while (gate_closed) { pthread_cond_wait(&cv, &mu); }
    calls++;
    seen_family = family;
    memcpy(seen_addr, addr, family == 6 ? 16 : 4);
    snprintf(seen_host, sizeof seen_host, "%s", host);
    seen_mark = mark;
    d2k_https_state s = answer;
    pthread_mutex_unlock(&mu);
    snprintf(why, cap, "подделка");
    return s;
}

static size_t wait_done(d2k_httpsprobe *p, int64_t now, d2k_httpsprobe_result *r, size_t cap) {
    for (int i = 0; i < 200; i++) {
        struct pollfd f = {d2k_httpsprobe_wake_fd(p), POLLIN, 0};
        (void)poll(&f, 1, 10);
        size_t n = d2k_httpsprobe_done(p, now, r, cap);
        if (n) { return n; }
    }
    return 0;
}

static void test_classify(void) {
    /* (3) 443 отказал / недостижим — HTTPS нет: портал как есть. */
    CHECK(d2k_https_classify(D2K_HTTPS_REFUSED, 0, 0, -1) == D2K_HTTPS_CLOSED, "отказ 443 не CLOSED");
    /* SYN к 443 без ответа: не «принимает», данных нет — не переводим. */
    CHECK(d2k_https_classify(D2K_HTTPS_NO_ANSWER, 0, 0, -1) == D2K_HTTPS_UNCONFIRMED,
          "тишина на SYN к 443 не UNCONFIRMED");
    /* (2) 443 принял, на наш ClientHello ни байта TLS от сервера — так режет коробка. */
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 0, 0, -1) == D2K_HTTPS_TLS_BLOCKED,
          "обрыв TLS без ответа сервера не TLS_BLOCKED");
    /* (1) TLS прошёл, имя в листе. */
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, 1, 1) == D2K_HTTPS_SERVED, "TLS с именем не SERVED");
    /* (3) сервер ответил TLS, но лист на другое имя. */
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, 1, 0) == D2K_HTTPS_OTHER_NAME,
          "TLS с чужим именем не OTHER_NAME");
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, 1, -1) == D2K_HTTPS_UNCONFIRMED,
          "TLS без прочитанного имени принят за подтверждение");
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, 0, -1) == D2K_HTTPS_UNCONFIRMED,
          "сервер ответил TLS, наш клиент не договорился — принято за блокировку");
    CHECK(d2k_https_upgrade(D2K_HTTPS_SERVED) && d2k_https_upgrade(D2K_HTTPS_TLS_BLOCKED) &&
          !d2k_https_upgrade(D2K_HTTPS_CLOSED) && !d2k_https_upgrade(D2K_HTTPS_OTHER_NAME) &&
          !d2k_https_upgrade(D2K_HTTPS_UNCONFIRMED) && !d2k_https_upgrade(D2K_HTTPS_PROBING),
          "307 не ровно для SERVED и TLS_BLOCKED");
    CHECK(d2k_https_ttl(D2K_HTTPS_SERVED) == 6u * 3600u && d2k_https_ttl(D2K_HTTPS_TLS_BLOCKED) == 3600u &&
          d2k_https_ttl(D2K_HTTPS_CLOSED) == 1800u && d2k_https_ttl(D2K_HTTPS_OTHER_NAME) == 1800u &&
          d2k_https_ttl(D2K_HTTPS_UNCONFIRMED) == 120u, "сроки не те");
}

static void test_flow(void) {
    d2k_httpsprobe *p = d2k_httpsprobe_new(0x2e, fake);
    CHECK(p != NULL, "зонд не создан");
    const uint8_t ip[4] = {195, 82, 146, 214};
    uint32_t ttl = 0;
    d2k_httpsprobe_result r[4];
    answer = D2K_HTTPS_SERVED;
    CHECK(d2k_httpsprobe_portal(p, "RuTracker.org", 4, ip, 0, 1000, &ttl) == 1, "зонд не поставлен");
    CHECK(d2k_httpsprobe_portal(p, "rutracker.org", 4, ip, 0, 1001, &ttl) == 0,
          "второй зонд по тому же имени поставлен");
    size_t n = wait_done(p, 1500, r, 4);
    CHECK(n == 1 && r[0].state == D2K_HTTPS_SERVED && r[0].ttl_s == 21600 &&
          strcmp(r[0].host, "RuTracker.org") == 0, "ответ зонда не тот");
    CHECK(seen_family == 4 && memcmp(seen_addr, ip, 4) == 0 && seen_mark == 0x2e &&
          strcmp(seen_host, "RuTracker.org") == 0, "зонд ушёл не туда");
    CHECK(d2k_httpsprobe_state(p, "RUTRACKER.ORG", 2000) == D2K_HTTPS_SERVED, "кэш не помнит имя");
    CHECK(d2k_httpsprobe_portal(p, "rutracker.org", 4, ip, 1, 3000, &ttl) == 0,
          "при ответе 307 датапатом зонд повторён");
    CHECK(d2k_httpsprobe_portal(p, "rutracker.org", 4, ip, 0, 1500 + 3600 * 1000, &ttl) == 2 &&
          ttl == 21600 - 3600, "датапат забыл имя — команда не повторена с остатком срока");
    CHECK(calls == 1, "лишний зонд");

    answer = D2K_HTTPS_TLS_BLOCKED;
    CHECK(d2k_httpsprobe_portal(p, "rutracker.cc", 4, ip, 0, 5000, &ttl) == 1, "зонд не поставлен");
    n = wait_done(p, 5100, r, 4);
    CHECK(n == 1 && r[0].state == D2K_HTTPS_TLS_BLOCKED && r[0].ttl_s == 3600,
          "TLS, срезанный коробкой, не TLS_BLOCKED");
    CHECK(d2k_httpsprobe_portal(p, "rutracker.cc", 4, ip, 0, 6000, &ttl) == 2 && ttl == 3599,
          "TLS_BLOCKED, забытый датапатом, не повторён");

    answer = D2K_HTTPS_CLOSED;
    CHECK(d2k_httpsprobe_portal(p, "www.fast-torrent.ru", 4, ip, 0, 10000, &ttl) == 1, "зонд не поставлен");
    n = wait_done(p, 10100, r, 4);
    CHECK(n == 1 && r[0].state == D2K_HTTPS_CLOSED && r[0].ttl_s == 1800, "закрытый 443 не тот");
    CHECK(d2k_httpsprobe_portal(p, "www.fast-torrent.ru", 4, ip, 0, 20000, &ttl) == 0,
          "свежий ответ «нет HTTPS» перепроверен");
    CHECK(d2k_httpsprobe_portal(p, "www.fast-torrent.ru", 4, ip, 0, 10100 + 1800 * 1000, &ttl) == 1,
          "истёкший ответ не перепроверен");
    (void)wait_done(p, 10100 + 1800 * 1000, r, 4);

    /* Очередь ограничена: зонды стоят, лишнее не копится. */
    pthread_mutex_lock(&mu); gate_closed = 1; pthread_mutex_unlock(&mu);
    char name[64];
    int queued = 0;
    for (int i = 0; i < D2K_HTTPSPROBE_JOBS + 8; i++) {
        snprintf(name, sizeof name, "n%d.example", i);
        queued += d2k_httpsprobe_portal(p, name, 4, ip, 0, 50000, &ttl) == 1;
    }
    CHECK(queued <= D2K_HTTPSPROBE_JOBS + 1, "очередь зондов не ограничена");
    CHECK(queued >= D2K_HTTPSPROBE_JOBS, "очередь зондов меньше объявленной");
    pthread_mutex_lock(&mu); gate_closed = 0; pthread_cond_broadcast(&cv); pthread_mutex_unlock(&mu);

    /* IPv6 и негодное имя. */
    const uint8_t ip6[16] = {0x2a, 0x02, [15] = 0x80};
    CHECK(d2k_httpsprobe_portal(p, "bad name", 6, ip6, 0, 60000, &ttl) == 0, "негодное имя пошло в зонд");
    d2k_httpsprobe_free(p);
}

/* Местный «443» с заданным поведением после ClientHello. */
enum { SRV_SILENT, SRV_CLOSE, SRV_RESET, SRV_HTTP, SRV_ALERT };
typedef struct { int fd, mode, accepted; } srv;

static void *serve(void *arg) {
    srv *v = arg;
    for (;;) {
        int c = accept(v->fd, NULL, NULL);
        if (c < 0) { return NULL; }
        v->accepted++;
        uint8_t buf[2048];
        if (v->mode != SRV_SILENT) { (void)recv(c, buf, sizeof buf, 0); }
        if (v->mode == SRV_HTTP) {
            static const char h[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            (void)send(c, h, sizeof h - 1, 0);
        } else if (v->mode == SRV_ALERT) {
            static const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
            (void)send(c, alert, sizeof alert, 0);
        } else if (v->mode == SRV_RESET) {
            struct linger l = {1, 0};
            (void)setsockopt(c, SOL_SOCKET, SO_LINGER, &l, sizeof l);
        } else if (v->mode == SRV_SILENT) {
            /* держим соединение открытым до конца зонда */
            (void)recv(c, buf, sizeof buf, 0);
            (void)recv(c, buf, sizeof buf, 0);
        }
        close(c);
    }
}

static d2k_https_state probe_against(int mode, char *why, size_t cap) {
    const uint8_t lo[4] = {127, 0, 0, 1};
    srv v = {socket(AF_INET, SOCK_STREAM, 0), mode, 0};
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    int one = 1;
    (void)setsockopt(v.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    CHECK(bind(v.fd, (struct sockaddr *)&a, sizeof a) == 0 && listen(v.fd, 8) == 0 &&
          getsockname(v.fd, (struct sockaddr *)&a, &al) == 0, "местный 443 не поднят");
    d2k_https_probe_port = ntohs(a.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, serve, &v);
    d2k_https_state st = d2k_https_probe_real(4, lo, "example.com", 0, why, cap);
    shutdown(v.fd, SHUT_RDWR);
    close(v.fd);
    pthread_join(th, NULL);
    d2k_https_probe_port = 443;
    return st;
}

static void test_real(void) {
    const uint8_t lo[4] = {127, 0, 0, 1};
    char why[256];
    /* Порт свободен: отказ — HTTPS нет. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0 &&
          getsockname(s, (struct sockaddr *)&a, &al) == 0, "местный порт не взят");
    close(s);
    d2k_https_probe_port = ntohs(a.sin_port);
    d2k_https_state st = d2k_https_probe_real(4, lo, "example.com", 0, why, sizeof why);
    CHECK(st == D2K_HTTPS_CLOSED, "отказ 443 не распознан как отсутствие HTTPS");
    d2k_https_probe_port = 443;

    static const struct { int mode; d2k_https_state want; const char *what; } cases[] = {
        {SRV_SILENT, D2K_HTTPS_TLS_BLOCKED, "тишина после ClientHello не TLS_BLOCKED"},
        {SRV_CLOSE,  D2K_HTTPS_TLS_BLOCKED, "закрытие после ClientHello не TLS_BLOCKED"},
        {SRV_RESET,  D2K_HTTPS_TLS_BLOCKED, "сброс после ClientHello не TLS_BLOCKED"},
        {SRV_HTTP,   D2K_HTTPS_TLS_BLOCKED, "не-TLS ответ (вставка HTTP) не TLS_BLOCKED"},
        {SRV_ALERT,  D2K_HTTPS_UNCONFIRMED, "TLS-тревога сервера принята за блокировку"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        st = probe_against(cases[i].mode, why, sizeof why);
        CHECK(st == cases[i].want, cases[i].what);
        if (st != cases[i].want) { printf("  состояние %d: %s\n", (int)st, why); }
    }
}

/* Кэш на диске: переживает перезапуск, срок соблюдается, мусор не роняет. */
static void test_persist(void) {
    char path[] = "/tmp/d2k-https-cacheXXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "временный файл");
    close(fd);
    unlink(path);
    char err[256];
    const uint8_t ip[4] = {1, 2, 3, 4};
    uint32_t ttl;
    d2k_httpsprobe_result r[8], push[8];
    size_t np = 0, nl = 0;

    d2k_httpsprobe *p = d2k_httpsprobe_new(0, fake);
    CHECK(d2k_httpsprobe_load(p, path, 0, 1000000, push, 8, &np, &nl, err, sizeof err) == 0 &&
          np == 0 && nl == 0, "отсутствующий файл — не пустой кэш");
    answer = D2K_HTTPS_SERVED;
    (void)d2k_httpsprobe_portal(p, "a.example", 4, ip, 0, 1000, &ttl);
    (void)wait_done(p, 1000, r, 8);
    answer = D2K_HTTPS_TLS_BLOCKED;
    (void)d2k_httpsprobe_portal(p, "b.example", 4, ip, 0, 1000, &ttl);
    (void)wait_done(p, 1000, r, 8);
    answer = D2K_HTTPS_CLOSED;
    (void)d2k_httpsprobe_portal(p, "c.example", 4, ip, 0, 1000, &ttl);
    (void)wait_done(p, 1000, r, 8);
    /* стенные часы при сохранении — 1 000 000 с */
    CHECK(d2k_httpsprobe_save(p, path, 1000, 1000000, err, sizeof err) == 0, "кэш не сохранён");
    d2k_httpsprobe_free(p);

    /* Перезапуск через 10 минут: всё живо, к датапату — только 307-классы. */
    p = d2k_httpsprobe_new(0, fake);
    CHECK(d2k_httpsprobe_load(p, path, 50, 1000000 + 600, push, 8, &np, &nl, err, sizeof err) == 0 &&
          nl == 3 && np == 2, "после перезапуска загружено не то");
    int got_a = 0, got_b = 0;
    for (size_t i = 0; i < np; i++) {
        if (!strcmp(push[i].host, "a.example") && push[i].state == D2K_HTTPS_SERVED &&
            push[i].ttl_s == 21600 - 600) { got_a = 1; }
        if (!strcmp(push[i].host, "b.example") && push[i].state == D2K_HTTPS_TLS_BLOCKED &&
            push[i].ttl_s == 3600 - 600) { got_b = 1; }
    }
    CHECK(got_a && got_b, "остаток срока или классы после загрузки не те");
    CHECK(d2k_httpsprobe_state(p, "c.example", 60) == D2K_HTTPS_CLOSED, "CLOSED не загружен");
    CHECK(d2k_httpsprobe_portal(p, "c.example", 4, ip, 0, 60, &ttl) == 0,
          "загруженный свежий ответ перепроверен");
    d2k_httpsprobe_free(p);

    /* Через 2 часа: TLS_BLOCKED и CLOSED истекли, SERVED жив. */
    p = d2k_httpsprobe_new(0, fake);
    CHECK(d2k_httpsprobe_load(p, path, 0, 1000000 + 7200, push, 8, &np, &nl, err, sizeof err) == 0 &&
          nl == 1 && np == 1 && !strcmp(push[0].host, "a.example"), "истёкшее загружено");
    d2k_httpsprobe_free(p);

    /* Часы роутера до NTP в прошлом (ревью N2): файл записан «в будущем» —
       сколько ему на самом деле, не узнать, и старое знание не оживает. */
    p = d2k_httpsprobe_new(0, fake);
    CHECK(d2k_httpsprobe_load(p, path, 0, 10, push, 8, &np, &nl, err, sizeof err) == 0 &&
          np == 0 && nl == 0, "кэш, записанный позже «сейчас», ожил при отстающих часах");
    d2k_httpsprobe_free(p);
    /* Старый формат без отметки записи читается, срок режется классом. */
    {
        FILE *g = fopen(path, "w");
        fprintf(g, "d2k-https 1\nserved 99999999 old.example\n");
        fclose(g);
        p = d2k_httpsprobe_new(0, fake);
        CHECK(d2k_httpsprobe_load(p, path, 0, 1000000, push, 8, &np, &nl, err, sizeof err) == 0 &&
              np == 1 && push[0].ttl_s == 21600, "старый формат не прочитан или срок не урезан");
        d2k_httpsprobe_free(p);
    }

    /* Негодные строки пропускаются, годные берутся. */
    FILE *f = fopen(path, "w");
    fprintf(f, "d2k-https 2 1000000\nserved 2000000 good.example\nserved x bad\nweird 2000000 w.example\n"
               "served 2000000 bad name\n\xff\xfe\nprobing 2000000 p.example\n");
    fclose(f);
    p = d2k_httpsprobe_new(0, fake);
    CHECK(d2k_httpsprobe_load(p, path, 0, 1000000, push, 8, &np, &nl, err, sizeof err) == 0 &&
          nl == 1 && np == 1 && !strcmp(push[0].host, "good.example"), "негодные строки не пропущены");
    d2k_httpsprobe_free(p);

    /* Чужой файл: отказ с причиной, кэш пуст. */
    f = fopen(path, "w");
    fprintf(f, "{\"json\": true}\n");
    fclose(f);
    p = d2k_httpsprobe_new(0, fake);
    err[0] = 0;
    CHECK(d2k_httpsprobe_load(p, path, 0, 1000000, push, 8, &np, &nl, err, sizeof err) == -1 &&
          err[0] && nl == 0, "чужой файл принят");
    d2k_httpsprobe_free(p);
    unlink(path);
}

int main(void) {
    test_classify();
    test_flow();
    test_real();
    test_persist();
    if (fails) { printf("test_httpsprobe: провалов %d\n", fails); return 1; }
    printf("test_httpsprobe: все проверки прошли\n");
    return 0;
}
