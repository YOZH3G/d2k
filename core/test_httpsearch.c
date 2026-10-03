/* test_httpsearch.c — поиск обхода открытого HTTP (задача 51, шаг 4). */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_httpsearch.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

static const char INJECT[] =
    "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\n"
    "Connection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";
static const char REAL[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>";

static void test_judge(void) {
    CHECK(d2k_hs_judge("rutracker.org", INJECT, sizeof INJECT - 1, 98000, 700) == D2K_HS_INJECTED,
          "вставка поля не узнана");
    CHECK(d2k_hs_judge("rutracker.org", INJECT, sizeof INJECT - 1, 98000, 120000) == D2K_HS_INJECTED,
          "поздний 302 на портал принят за сервер");
    CHECK(d2k_hs_judge("rutracker.org", REAL, sizeof REAL - 1, 98000, 99000) == D2K_HS_REAL,
          "ответ сервера не узнан");
    CHECK(d2k_hs_judge("rutracker.org", REAL, sizeof REAL - 1, 98000, 1000) == D2K_HS_EARLY,
          "ответ быстрее RTT/2 принят за сервер");
    static const char own[] = "HTTP/1.1 301 Moved\r\nLocation: https://rutracker.org/\r\n\r\n";
    CHECK(d2k_hs_judge("rutracker.org", own, sizeof own - 1, 98000, 99000) == D2K_HS_REAL,
          "редирект сервера на свой https не принят за ответ сервера");
    CHECK(d2k_hs_judge("rutracker.org", "\x16\x03\x01", 3, 98000, 99000) == D2K_HS_GARBAGE,
          "не-HTTP принят за ответ");
    CHECK(d2k_hs_judge("rutracker.org", "HTTP/1.1", 8, 98000, 99000) == D2K_HS_GARBAGE,
          "обрывок строки статуса принят за ответ");
}

/* Кандидаты: каждый — годный план протокола http, исполнимый на запросе. */
static void test_candidates(void) {
    CHECK(d2k_hs_candidate_count() >= 4, "кандидатов меньше заявленных вопросов");
    static const char req[] = "GET / HTTP/1.1\r\nHost: rutracker.org\r\nAccept: */*\r\n\r\n";
    const uint8_t id[16] = {1, 2, 3};
    for (size_t i = 0; i < d2k_hs_candidate_count(); i++) {
        char text[2048];
        const char *k = d2k_hs_candidate_key(i);
        CHECK(k && d2k_hs_candidate_text(k, id, text, sizeof text) == 0, "текст кандидата не собран");
        uint8_t tlv[4096];
        size_t tl = 0;
        char err[200];
        if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tl, err, sizeof err) != 0) {
            printf("  %s: %s\n", k, err);
            fails++;
            continue;
        }
        d2k_plan *p = NULL;
        CHECK(d2k_plan_load(tlv, tl, &p, err, sizeof err) == 0 && p, "план кандидата не принят датапатом");
        if (!p) { continue; }
        CHECK(d2k_plan_proto(p) == D2K_PLAN_PROTO_HTTP && d2k_plan_transport(p) == 6,
              "план кандидата не объявляет HTTP поверх TCP");
        CHECK(!memcmp(d2k_plan_id(p), id, 16), "идентификатор плана не тот");
        d2k_pkt in;
        memset(&in, 0, sizeof in);
        in.payload = (const uint8_t *)req;
        in.payload_len = sizeof req - 1;
        in.seq = 1000;
        in.is_http = 1;
        in.have_sni = 1;
        in.sni_off = (size_t)(strstr(req, "rutracker") - req);
        in.sni_len = 13;
        d2k_actions acts;
        CHECK(d2k_plan_apply(p, NULL, &in, &acts) == 0 && acts.n >= 2 &&
              acts.fate == D2K_ORIG_DROP, "кандидат не режет запрос");
        d2k_actions_free(&acts);
        in.is_http = 0;
        CHECK(d2k_plan_apply(p, NULL, &in, &acts) != 0, "HTTP-кандидат исполнился на не-HTTP входе");
        d2k_plan_free(p);
    }
    char text[2048];
    CHECK(d2k_hs_candidate_text("nonsense", id, text, sizeof text) != 0, "неизвестный кандидат собран");
}

/* --- настоящий зонд против местного сервера -------------------------------- */
typedef struct { int fd; const char *answer; int delay_ms; int close_only; } srv;
static void *serve(void *arg) {
    srv *v = arg;
    int c = accept(v->fd, NULL, NULL);
    if (c < 0) { return NULL; }
    char buf[2048];
    (void)recv(c, buf, sizeof buf, 0);
    if (v->delay_ms) {
        struct timespec ts = {0, (long)v->delay_ms * 1000000L};
        nanosleep(&ts, NULL);
    }
    if (v->answer) { (void)send(c, v->answer, strlen(v->answer), 0); }
    if (!v->close_only && !v->answer) { (void)recv(c, buf, sizeof buf, 0); }
    close(c);
    return NULL;
}

static d2k_hs_answer probe_local(const char *answer, int close_only, char *status, size_t cap) {
    /* Ответ — не раньше RTT/2: местный RTT в десятки мкс, задержка 20 мс
       исключает случайный «слишком ранний» ответ. */
    srv v = {socket(AF_INET, SOCK_STREAM, 0), answer, 20, close_only};
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    int one = 1;
    (void)setsockopt(v.fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(v.fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(v.fd, 4) != 0 ||
        getsockname(v.fd, (struct sockaddr *)&a, &al) != 0) { return D2K_HS_NONE; }
    d2k_hs_probe_port = ntohs(a.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, serve, &v);
    d2k_hs_job job;
    memset(&job, 0, sizeof job);
    job.fd = socket(AF_INET, SOCK_STREAM, 0);
    job.family = 4;
    job.addr[0] = 127; job.addr[3] = 1;
    snprintf(job.host, sizeof job.host, "rutracker.org");
    d2k_hs_result r;
    d2k_hs_probe_run(&job, &r);
    close(job.fd);   /* сокет зонда закрывает владелец, а не d2k_hs_probe_run */
    shutdown(v.fd, SHUT_RDWR);
    close(v.fd);
    pthread_join(th, NULL);
    if (status) { snprintf(status, cap, "%s", r.status); }
    return r.answer;
}

static void test_probe(void) {
    d2k_hs_probe_ms = 800;
    char st[64];
    /* Локальный RTT ~0: ответ «раньше RTT/2» невозможен, судит содержимое. */
    CHECK(probe_local(INJECT, 0, st, sizeof st) == D2K_HS_INJECTED, "зонд не узнал вставку");
    CHECK(probe_local(REAL, 0, st, sizeof st) == D2K_HS_REAL && !strcmp(st, "HTTP/1.1 200 OK"),
          "зонд не узнал ответ сервера");
    CHECK(probe_local(NULL, 1, NULL, 0) == D2K_HS_CLOSED, "закрытие без ответа не узнано");
    CHECK(probe_local(NULL, 0, NULL, 0) == D2K_HS_SILENT, "молчание не узнано");
    /* Закрытый порт. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001u);
    socklen_t al = sizeof a;
    (void)bind(s, (struct sockaddr *)&a, sizeof a);
    (void)getsockname(s, (struct sockaddr *)&a, &al);
    close(s);
    d2k_hs_probe_port = ntohs(a.sin_port);
    d2k_hs_job job;
    memset(&job, 0, sizeof job);
    job.fd = socket(AF_INET, SOCK_STREAM, 0);
    job.family = 4; job.addr[0] = 127; job.addr[3] = 1;
    snprintf(job.host, sizeof job.host, "rutracker.org");
    d2k_hs_result r;
    d2k_hs_probe_run(&job, &r);
    close(job.fd);
    CHECK(r.answer == D2K_HS_CONNECT_FAIL, "отказ соединения не узнан");
    d2k_hs_probe_port = 80;
    d2k_hs_probe_ms = 6000;
}

/* --- машина поиска с подделанным вводом-выводом ----------------------------- */
typedef struct {
    int next_fd, open_n, close_n, set_probe_n, del_probe_n, set_plan_n, del_plan_n, start_n, changed_n;
    uint16_t sport;
    char last_probe_plan[2048], last_plan[2048], last_plan_host[256], said[8192];
    uint8_t trial[16], plan_id[16];
    d2k_hs_job job;
    int fail_ack;
} fake;

static int f_open(void *c, uint8_t fam, int *fd, uint16_t *sport) {
    fake *f = c; (void)fam; f->open_n++; *fd = 100 + f->next_fd++; *sport = ++f->sport; return 0;
}
static void f_close(void *c, int fd) { (void)fd; ((fake *)c)->close_n++; }
static int hexval(char c) { return c >= 'a' ? c - 'a' + 10 : c - '0'; }
static int f_set_probe(void *c, const char *h, uint8_t fam, uint16_t sp, const char *text,
                       const uint8_t trial[16]) {
    fake *f = c; (void)h; (void)fam; (void)sp;
    f->set_probe_n++;
    snprintf(f->last_probe_plan, sizeof f->last_probe_plan, "%s", text);
    memcpy(f->trial, trial, 16);
    const char *id = strstr(text, "\nid ");
    if (id) { for (int i = 0; i < 16; i++) f->plan_id[i] = (uint8_t)(hexval(id[4 + 2 * i]) << 4 | hexval(id[5 + 2 * i])); }
    return 0;
}
static int f_del_probe(void *c, const char *h, uint8_t fam, uint16_t sp) {
    (void)h; (void)fam; (void)sp; ((fake *)c)->del_probe_n++; return 0;
}
static int f_set_plan(void *c, const char *h, uint8_t fam, const char *text) {
    fake *f = c; (void)fam; f->set_plan_n++;
    snprintf(f->last_plan, sizeof f->last_plan, "%s", text);
    snprintf(f->last_plan_host, sizeof f->last_plan_host, "%s", h);
    return 0;
}
static int f_del_plan(void *c, const char *h, uint8_t fam) { (void)h; (void)fam; ((fake *)c)->del_plan_n++; return 0; }
static int f_start(void *c, const d2k_hs_job *j) { fake *f = c; f->start_n++; f->job = *j; return 0; }
static void f_say(void *c, const char *line) {
    fake *f = c;
    size_t n = strlen(f->said);
    if (n < sizeof f->said - 2) { snprintf(f->said + n, sizeof f->said - n, "%s\n", line); }
}
static void f_changed(void *c) { ((fake *)c)->changed_n++; }

static d2k_hs_ops ops_of(fake *f) {
    d2k_hs_ops o = {f_open, f_close, f_set_probe, f_del_probe, f_set_plan, f_del_plan,
                    f_start, f_say, f_changed, f};
    return o;
}

static d2k_hs_result res(d2k_hs_answer a) {
    d2k_hs_result r;
    memset(&r, 0, sizeof r);
    r.answer = a; r.rtt_us = 98000; r.reply_us = a == D2K_HS_INJECTED ? 700 : 99000;
    return r;
}

static const uint8_t IP[16] = {37, 221, 67, 160};

/* Одно испытание: подтверждение, зонд, APPLIED (если applied), ответ. */
static void trial(d2k_httpsearch *hs, fake *f, int64_t *now, int applied, d2k_hs_answer a) {
    int before = f->start_n;
    d2k_httpsearch_ack(hs, f->trial, 1, *now += 10);
    CHECK(f->start_n == before + 1 && f->job.fd >= 100, "после подтверждения зонд не запущен своим сокетом");
    if (applied) { d2k_httpsearch_applied(hs, f->plan_id); }
    d2k_hs_result r = res(a);
    r.seq = f->job.seq;
    r.fd = f->job.fd;
    d2k_httpsearch_result(hs, &r, *now += 100);
}

static void test_search(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 4, IP, now);
    CHECK(f.start_n == 1 && f.set_probe_n == 0, "база: зонд без плана не запущен");
    d2k_hs_result r = res(D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    /* Вопрос 1 — разрез Host. */
    CHECK(f.set_probe_n == 1 && strstr(f.last_probe_plan, "split sni_middle") &&
          strstr(f.last_probe_plan, "proto tcp http") && !strstr(f.last_probe_plan, "fake"),
          "первый вопрос — не разрез Host");
    /* Повторная вставка во время поиска нового поиска не начинает. */
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 4, IP, now);
    CHECK(f.set_probe_n == 1 && f.start_n == 1, "повторная вставка сорвала идущий поиск");
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);
    CHECK(f.del_probe_n == 1 && f.close_n >= 1, "пробный план не снят после испытания");
    /* Вопрос 2 — тот же разрез, хвост первым. */
    CHECK(f.set_probe_n == 2 && strstr(f.last_probe_plan, "order reverse"), "второй вопрос — не обратный порядок");
    /* Исполнения не было — кандидат не судим, идём дальше. */
    trial(hs, &f, &now, 0, D2K_HS_REAL);
    CHECK(f.set_plan_n == 0 && f.set_probe_n == 2, "кандидат без исполнения судим до срока APPLIED");
    d2k_httpsearch_tick(hs, now += 1000);
    CHECK(f.set_plan_n == 0, "кандидат без исполнения на проводе подтверждён");
    CHECK(strstr(f.said, "не исполнен") != NULL, "неисполнение не названо");
    /* Вопрос 3 — приманка с испорченной суммой. Отказ датапата — тоже не суд. */
    CHECK(f.set_probe_n == 3 && strstr(f.last_probe_plan, "badsum"), "третий вопрос — не приманка badsum");
    d2k_httpsearch_ack(hs, f.trial, 0, now += 10);
    CHECK(f.start_n == 3, "отвергнутый датапатом кандидат всё равно испытан");
    /* Вопрос 4 — приманка вне окна: настоящий ответ, затем подтверждение. */
    CHECK(f.set_probe_n == 4 && strstr(f.last_probe_plan, "seqshift"), "четвёртый вопрос — не приманка seqshift");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 0 && f.set_probe_n == 5 && strstr(f.last_probe_plan, "seqshift"),
          "успех не перепроверен тем же кандидатом");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 1 && !strcmp(f.last_plan_host, "www.fast-torrent.ru") &&
          strstr(f.last_plan, "seqshift") && strstr(f.last_plan, "proto tcp http") && f.changed_n == 1,
          "подтверждённый план не поставлен постоянным");
    CHECK(!d2k_httpsearch_busy(hs), "поиск не закончился");
    CHECK(d2k_httpsearch_plan_of(hs, "WWW.FAST-TORRENT.RU", 4) &&
          !strcmp(d2k_httpsearch_plan_of(hs, "www.fast-torrent.ru", 4), "fake-seqshift"),
          "подтверждённый кандидат не запомнен");
    CHECK(f.open_n == f.close_n, "сокеты зондов не закрыты");

    /* Второе имя: сначала свой подтверждённый план. */
    int sp = f.set_probe_n;
    d2k_httpsearch_portal(hs, "rutracker.org", 4, IP, now += 1000);
    r = res(D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp + 1 && strstr(f.last_probe_plan, "seqshift"),
          "свой подтверждённый план не испытан первым");
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(f.set_plan_n == 2, "свой план для второго имени не подтверждён");

    /* База без вставки — блокировка не воспроизводится, вопросов нет. */
    sp = f.set_probe_n;
    d2k_httpsearch_portal(hs, "free.example", 4, IP, now += 1000);
    r = res(D2K_HS_REAL);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp && !d2k_httpsearch_busy(hs) && strstr(f.said, "не воспроизвод"),
          "поиск начат без воспроизведённой вставки");
    /* Вставка по имени с планом — перепроверка: план испытан первым. */
    sp = f.set_probe_n;
    d2k_httpsearch_portal(hs, "rutracker.org", 4, IP, now += D2K_HS_RECHECK_MS + 1);
    r = res(D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == sp + 1 && strstr(f.last_probe_plan, "seqshift"), "перепроверка не начата своим планом");
    /* Все вопросы мимо — план снят, имя ждёт D2K_HS_RETRY_MS. */
    for (int i = 0; i < 8 && d2k_httpsearch_busy(hs); i++) { trial(hs, &f, &now, 1, D2K_HS_INJECTED); }
    CHECK(!d2k_httpsearch_busy(hs) && f.del_plan_n == 1 && !d2k_httpsearch_plan_of(hs, "rutracker.org", 4),
          "неработающий план не снят после перепроверки");
    int st = f.start_n;
    d2k_httpsearch_portal(hs, "rutracker.org", 4, IP, now += 1000);
    CHECK(f.start_n == st, "имя без обхода перепроверено раньше срока");

    /* Сроки: нет подтверждения — проба снята, следующий кандидат. */
    d2k_httpsearch_portal(hs, "slow.example", 4, IP, now += 1000);
    r = res(D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    int dp = f.del_probe_n, spn = f.set_probe_n;
    d2k_httpsearch_tick(hs, now += 60000);
    CHECK(f.del_probe_n == dp + 1 && f.set_probe_n == spn + 1, "срок подтверждения не соблюдён");
    d2k_httpsearch_free(hs);
    CHECK(f.open_n == f.close_n, "сокеты зондов не закрыты при освобождении");
}

/* Ревью I-2: неизмеренный поиск не снимает план и не ставит часовую паузу. */
static void base_injected(d2k_httpsearch *hs, fake *f, int64_t *now) {
    d2k_hs_result r = res(D2K_HS_INJECTED);
    r.seq = f->job.seq; r.fd = f->job.fd;
    d2k_httpsearch_result(hs, &r, *now += 100);
}
static void test_inconclusive(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    /* Первый поиск: датапат отверг все пробы — не измерено. */
    d2k_httpsearch_portal(hs, "a.example", 4, IP, now);
    base_injected(hs, &f, &now);
    for (int i = 0; i < 8 && d2k_httpsearch_busy(hs); i++) {
        d2k_httpsearch_ack(hs, f.trial, 0, now += 10);
    }
    CHECK(!d2k_httpsearch_busy(hs) && strstr(f.said, "не измерен") && !strstr(f.said, "обход не найден"),
          "отказы датапата названы «обход не найден»");
    int st = f.start_n;
    d2k_httpsearch_portal(hs, "a.example", 4, IP, now + D2K_HS_INCONCLUSIVE_MS + 1);
    CHECK(f.start_n == st + 1, "после неизмеренного поиска повтор отложен на час");
    while (d2k_httpsearch_busy(hs)) { d2k_httpsearch_tick(hs, now += 60000); }

    /* Перепроверка подтверждённого плана, где ни одно исполнение не
       подтвердилось (APPLIED потерян) — план остаётся. */
    now += 10 * D2K_HS_RETRY_MS;
    d2k_httpsearch_portal(hs, "b.example", 4, IP, now);
    base_injected(hs, &f, &now);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    CHECK(d2k_httpsearch_plan_of(hs, "b.example", 4) != NULL, "план b.example не подтверждён");
    d2k_httpsearch_portal(hs, "b.example", 4, IP, now += D2K_HS_RECHECK_MS + 1);
    base_injected(hs, &f, &now);
    for (int i = 0; i < 8 && d2k_httpsearch_busy(hs); i++) {
        trial(hs, &f, &now, 0, D2K_HS_INJECTED);
        d2k_httpsearch_tick(hs, now += 1000);
    }
    CHECK(!d2k_httpsearch_busy(hs) && f.del_plan_n == 0 && d2k_httpsearch_plan_of(hs, "b.example", 4),
          "перепроверка без единого исполнения сняла план");
    d2k_httpsearch_free(hs);
}

/* Измеренная порча (каталог TLS-коробок этой линии) — вместо заготовок. */
static void test_measured_poison(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_measured_poison(hs, "ttl=5 badsum") == 0, "измеренная порча не принята");
    CHECK(d2k_httpsearch_measured_poison(hs, "tcpts") != 0, "порча, которую HTTP-исполнитель не повторит, принята");
    CHECK(d2k_httpsearch_measured_poison(hs, "badsum") == 0, "измеренная badsum не принята");
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "c.example", 4, IP, now);
    base_injected(hs, &f, &now);
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);   /* split */
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);   /* disorder */
    CHECK(strstr(f.last_probe_plan, "fake payload=1") && strstr(f.last_probe_plan, "ttl=5") &&
          strstr(f.last_probe_plan, "badsum"), "третий вопрос — не измеренная порча");
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);
    CHECK(strstr(f.last_probe_plan, "badsum") && !strstr(f.last_probe_plan, "ttl="),
          "четвёртый вопрос — не вторая измеренная порча");
    trial(hs, &f, &now, 1, D2K_HS_INJECTED);
    CHECK(!d2k_httpsearch_busy(hs) && !strstr(f.last_probe_plan, "seqshift"),
          "при измеренной порче заданы и заготовки");
    /* Извлечение из текста подтверждённого TLS-плана (как в каталоге). */
    static const char tls[] = "d2k-plan 1 1\nid 00\nproto tcp tls\npayload 1 16\npayload 2 41\n"
        "poison 1 badsum\npoison 2 ttl=4\nsplit hello_middle +0\n"
        "fake payload=1 poison=1 repeats=2 gap_us=20000 place=before\n"
        "seqovl payload=2 poison=2\norder reverse\n";
    char sp[8][64];
    CHECK(d2k_hs_plan_poisons(tls, sp, 8) == 1 && !strcmp(sp[0], "badsum"),
          "порча приманки не извлечена или взята порча перекрытия");
    CHECK(d2k_hs_plan_poisons("d2k-plan 1 11\nid 00\nproto tcp http\npoison 1 badsum\n"
                              "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\n", sp, 8) == 0,
          "порча взята из не-TLS плана");
    char text[2048];
    const uint8_t id[16] = {1};
    CHECK(d2k_hs_candidate_text("fake:ttl=5+badsum", id, text, sizeof text) == 0 &&
          strstr(text, "poison 1 ttl=5 badsum"), "ключ измеренной порчи не собирается в план");
    CHECK(d2k_hs_candidate_text("fake:tcpts", id, text, sizeof text) != 0, "негодный ключ порчи собран");
    d2k_httpsearch_free(hs);
}

/* Ревью M-7: ответ чужого (устаревшего) зонда не судит текущий опыт. */
static void test_stale_result(void) {
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "d.example", 4, IP, now);
    d2k_hs_result r = res(D2K_HS_INJECTED);
    r.seq = f.job.seq + 7; r.fd = 999;
    int cl = f.close_n;
    d2k_httpsearch_result(hs, &r, now += 100);
    CHECK(f.set_probe_n == 0 && f.close_n == cl + 1, "ответ чужого зонда принят или его сокет не закрыт");
    d2k_httpsearch_free(hs);
}

static void test_persist(void) {
    char path[] = "/tmp/d2k-http-plansXXXXXX";
    int fd = mkstemp(path);
    close(fd);
    fake f;
    memset(&f, 0, sizeof f);
    d2k_hs_ops ops = ops_of(&f);
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    int64_t now = 1000;
    d2k_httpsearch_portal(hs, "www.fast-torrent.ru", 6, IP, now);
    d2k_hs_result r = res(D2K_HS_INJECTED);
    r.seq = f.job.seq; r.fd = f.job.fd;
    d2k_httpsearch_result(hs, &r, now += 100);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    trial(hs, &f, &now, 1, D2K_HS_REAL);
    char err[256];
    CHECK(d2k_httpsearch_save(hs, path, 1700000000, err, sizeof err) == 0, "планы не сохранены");
    d2k_httpsearch_free(hs);

    memset(&f, 0, sizeof f);
    hs = d2k_httpsearch_new(&ops);
    size_t n = 0;
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == 0 && n == 1 && f.set_plan_n == 1 &&
          !strcmp(f.last_plan_host, "www.fast-torrent.ru") && strstr(f.last_plan, "split sni_middle"),
          "план не восстановлен после перезапуска");
    CHECK(d2k_httpsearch_plan_of(hs, "www.fast-torrent.ru", 6) && !d2k_httpsearch_plan_of(hs, "www.fast-torrent.ru", 4),
          "семейство плана потеряно");
    d2k_httpsearch_push_all(hs);
    CHECK(f.set_plan_n == 2, "переустановка планов не сработала");
    d2k_httpsearch_free(hs);

    FILE *g = fopen(path, "w");
    fprintf(g, "d2k-http-plans 1\nok.example 4 split 1700000000\nbad name 4 split 1\n"
               "x.example 4 nonsense 1\ny.example 5 split 1\nz.example 4 split\n");
    fclose(g);
    memset(&f, 0, sizeof f);
    hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == 0 && n == 1 && f.set_plan_n == 1,
          "негодные строки не пропущены");
    d2k_httpsearch_free(hs);
    g = fopen(path, "w");
    fprintf(g, "{}\n");
    fclose(g);
    memset(&f, 0, sizeof f);
    hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == -1 && f.set_plan_n == 0, "чужой файл принят");
    d2k_httpsearch_free(hs);
    unlink(path);
    hs = d2k_httpsearch_new(&ops);
    CHECK(d2k_httpsearch_load(hs, path, &n, err, sizeof err) == 0 && n == 0, "нет файла — не пустой список");
    d2k_httpsearch_free(hs);
}

int main(void) {
    test_judge();
    test_candidates();
    test_probe();
    test_search();
    test_persist();
    test_inconclusive();
    test_measured_poison();
    test_stale_result();
    if (fails) { printf("test_httpsearch: провалов %d\n", fails); return 1; }
    printf("test_httpsearch: все проверки прошли\n");
    return 0;
}
