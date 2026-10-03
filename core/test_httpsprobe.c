/* test_httpsprobe.c — HTTPS имени для перевода вставки на https (задача 51). */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
    CHECK(d2k_https_classify(D2K_HTTPS_REFUSED, 0, -1) == D2K_HTTPS_CLOSED, "отказ 443 не CLOSED");
    CHECK(d2k_https_classify(D2K_HTTPS_NO_ANSWER, 0, -1) == D2K_HTTPS_UNCONFIRMED,
          "тишина 443 не UNCONFIRMED");
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 0, -1) == D2K_HTTPS_UNCONFIRMED,
          "оборванный TLS не UNCONFIRMED");
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, 1) == D2K_HTTPS_SERVED, "TLS с именем не SERVED");
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, 0) == D2K_HTTPS_OTHER_NAME,
          "TLS с чужим именем не OTHER_NAME");
    CHECK(d2k_https_classify(D2K_HTTPS_CONNECTED, 1, -1) == D2K_HTTPS_UNCONFIRMED,
          "TLS без прочитанного имени принят за подтверждение");
    CHECK(d2k_https_ttl(D2K_HTTPS_SERVED) == 6u * 3600u && d2k_https_ttl(D2K_HTTPS_CLOSED) == 1800u &&
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

/* Настоящий зонд на местных портах: отказ и обрыв без TLS. */
static void test_real(void) {
    const uint8_t lo[4] = {127, 0, 0, 1};
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    CHECK(s >= 0 && bind(s, (struct sockaddr *)&a, sizeof a) == 0 &&
          getsockname(s, (struct sockaddr *)&a, &al) == 0, "местный порт не взят");
    d2k_https_probe_port = ntohs(a.sin_port);
    char why[256];
    /* Порт свободен (сокет закрыт): отказ. */
    close(s);
    d2k_https_state refused = d2k_https_probe_real(4, lo, "example.com", 0, why, sizeof why);
    CHECK(refused == D2K_HTTPS_CLOSED, "отказ 443 не распознан как отсутствие HTTPS");
    if (refused != D2K_HTTPS_CLOSED) { printf("  состояние %d: %s\n", (int)refused, why); }
    /* Слушает и молчит: TLS не завершился. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s >= 0 && bind(s, (struct sockaddr *)&a, sizeof a) == 0 && listen(s, 4) == 0, "listen");
    d2k_https_state st = d2k_https_probe_real(4, lo, "example.com", 0, why, sizeof why);
    CHECK(st == D2K_HTTPS_UNCONFIRMED, "молчаливый 443 принят за HTTPS или за отказ");
    close(s);
    d2k_https_probe_port = 443;
}

int main(void) {
    test_classify();
    test_flow();
    test_real();
    if (fails) { printf("test_httpsprobe: провалов %d\n", fails); return 1; }
    printf("test_httpsprobe: все проверки прошли\n");
    return 0;
}
