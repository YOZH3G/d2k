#define _POSIX_C_SOURCE 200809L
/* SO_MARK — НЕ POSIX, и под строгим _POSIX_C_SOURCE библиотека его ПРЯЧЕТ.
 * Молча: #ifdef не срабатывает, компилятор не ругается, метка просто не
 * ставится ни на одном зонде — и замер меряет наш же обход поверх коробки.
 * Та же причина и то же лекарство, что в core/meas.c и datapath/raw.c.
 * Ловится это только счётчиком iptables, то есть уже на роутере. */
#define _DEFAULT_SOURCE 1

/* response.c — ОТВЕТНОЕ НАПРАВЛЕНИЕ. Перенос internal/classify/response.go.
 *
 * Всё остальное в этом модуле меряет направление клиент → сервер: проходит ли
 * НАШ ClientHello. Но у TLS 1.2 есть класс блокировки, которого при таком
 * замере не видно вовсе.
 *
 * В TLS 1.2 сертификат сервера едет ОТКРЫТЫМ ТЕКСТОМ и содержит имя домена.
 * Коробка может пропустить запрос и убить ОТВЕТ — на сертификате. Тогда наш
 * ClientHello доходит, ServerHello возвращается, инструмент честно объявляет
 * «проходит как есть», а сайт у человека не открывается. Вердикт получается не
 * просто неточным, а противоположным правде.
 *
 * В TLS 1.3 такого класса не существует: там всё после ServerHello уже
 * зашифровано, и резать по имени в сертификате нечего. Поэтому зонд насильно
 * договаривается на 1.2 — именно так коробка увидела бы сертификат в открытую.
 *
 * Оракул тот же, что и везде: сравнение с контролем. Рукопожатие с нейтральным
 * именем на ТОТ ЖЕ адрес обязано доходить. Не доходит — значит сервер не умеет
 * 1.2 или мешает что-то ещё, и вывода мы не делаем.
 *
 * ЕДИНСТВЕННОЕ ОТЛИЧИЕ ОТ ЭТАЛОНА, И ОНО НАЗВАНО ЗДЕСЬ. Там рукопожатие
 * доводится до конца средствами crypto/tls; здесь критерий — дошёл ли до нас
 * ServerHelloDone (тип 14). Это ТА ЖЕ граница: коробка режет ответ на записи с
 * сертификатом, то есть ДО ServerHelloDone, и ни одно рукопожатие 1.2 её не
 * переживает. Разница только в том, что критерий не требует своей реализации
 * обмена ключами — а лишний код в оракуле это лишний способ соврать. Случай, в
 * котором ответы разойдутся, ровно один: сервер прислал весь свой флайт, но
 * сломался бы позже, на нашем ClientKeyExchange. Это несовместимость клиента,
 * а не цензура, и эталон назвал бы её «режут ответ» ошибочно.
 */
#include "d2k_detect.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_MARK
#define SO_MARK 36
#endif

/* respTimeout — потолок на одно рукопожатие проверки.
 *
 * Он НИЖЕ общего: сюда мы попадаем только тогда, когда сервер уже ответил на
 * наш ClientHello, то есть он рядом и жив. Ждать его шесть секунд незачем, а
 * цена ожидания — прямое время в глазах человека. */
static int resp_timeout(const d2k_opts *opt)
{
    if (opt->timeout_ms > 0 && opt->timeout_ms < 3000) {
        return opt->timeout_ms;
    }
    return 3000;
}

/* Разбор потока записей TLS 1.2 по всему накопленному буферу.
 *
 * Сообщения рукопожатия тип(1) длина(3) могут быть разорваны между записями
 * (Certificate больше 16 КБ), поэтому границы сообщений ищем в СКЛЕЕННОМ потоке
 * payload записей типа 22, а не внутри каждой записи. Поток не копируем:
 * держим только счётчик байтов заголовка и остаток тела текущего сообщения, так
 * что память ограничена входным буфером (64 КБ), а байт 0x0e внутри тела
 * сертификата за ServerHelloDone не принимается.
 *
 * Возврат: 0 — продолжать читать; 1 — конец (*done=1: ServerHelloDone,
 * *done=0: фатальный алерт). Недочитанная запись — это 0, не «дошло». */
int d2k_resp_scan12(const uint8_t *buf, size_t have, int *done)
{
    size_t pos = 0, i;
    uint8_t hdr[4];
    size_t hgot = 0, body = 0;

    *done = 0;
    while (have - pos >= 5) {
        size_t rlen = ((size_t)buf[pos + 3] << 8) | buf[pos + 4];
        if (have - pos < 5 + rlen) {
            break;
        }
        if (buf[pos] == 0x15) {
            return 1;
        }
        if (buf[pos] == 0x16) {
            for (i = pos + 5; i < pos + 5 + rlen; i++) {
                if (body > 0) {
                    body--;
                    continue;
                }
                hdr[hgot++] = buf[i];
                if (hgot == 4) {
                    hgot = 0;
                    body = ((size_t)hdr[1] << 16) | ((size_t)hdr[2] << 8) | hdr[3];
                    if (hdr[0] == 14 && body == 0) {
                        *done = 1;
                        return 1;
                    }
                }
            }
        }
        pos += 5 + rlen;
    }
    return 0;
}

/* Ждём ServerHelloDone, разбирая поток записей TLS. Возврат 1 — дошёл. */
/* 1 — ServerHelloDone; 0 — не завершилось (алерт, обрыв, тишина); -1 — НЕ ИЗМЕРЕНО:
 * упёрлись в собственный предел буфера, про сервер это ничего не говорит. */
int d2k_resp_handshake12(const char *host, const char *port, const char *sni,
                       const d2k_opts *opt)
{
    d2k_trigger tr;
    char err[160];
    struct addrinfo hints, *ai = NULL;
    int fd = -1, rc = 0;
    int to = resp_timeout(opt);
    long deadline;
    enum { RESPONSE_CAP = 65536 };
    uint8_t *buf; /* heap-owned: each handshake has its own partial records */
    size_t have = 0;

    if (d2k_trigger_tls(sni, 1 /* legacy: без supported_versions, сервер пойдёт на 1.2 */,
                        &tr, err, sizeof(err)) != 0) {
        return 0;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = strchr(host, ':') ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &ai) != 0 || !ai) {
        return 0;
    }
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(ai);
        return 0;
    }
    {
        int mark = (int)(opt->mark ? opt->mark : (uint32_t)D2K_BYPASS_MARK);
        int one = 1;
        struct timeval tv;
        (void)setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        tv.tv_sec = to / 1000;
        tv.tv_usec = (to % 1000) * 1000;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        freeaddrinfo(ai);
        close(fd);
        return 0;
    }
    freeaddrinfo(ai);

    if (d2k_send_nosig(fd, tr.payload, tr.len) != (ssize_t)tr.len) {
        close(fd);
        return 0;
    }

    buf = malloc(RESPONSE_CAP);
    if (!buf) { close(fd); return 0; }
    deadline = d2k_now_ms() + to;
    while (d2k_now_ms() < deadline) {
        struct pollfd pfd;
        ssize_t n;
        int left = (int)(deadline - d2k_now_ms());

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, left < 0 ? 0 : left) <= 0) {
            break;
        }
        n = recv(fd, buf + have, RESPONSE_CAP - have, 0);
        if (n <= 0) {
            break;
        }
        have += (size_t)n;

        if (d2k_resp_scan12(buf, have, &rc) != 0) {
            goto out; /* ServerHelloDone, либо фатальный алерт */
        }
        if (have == RESPONSE_CAP) {
            rc = -1; /* локальный предел, а не поведение сети */
            break;
        }
    }
out:
    free(buf);
    close(fd);
    return rc;
}

/* countHandshakes считает, сколько рукопожатий TLS 1.2 дошли до конца.
 *
 * ПОСЛЕДОВАТЕЛЬНО, А НЕ ВЕЕРОМ. В эталоне повторы идут параллельно ради
 * времени (на rutracker.org прогон вырос с 4 до 39 секунд), но там за это
 * платит рантайм Go, а здесь пришлось бы заводить потоки ради одной функции.
 * Цена честная и названа: до полуминуты на заблокированной цели. */
static int count_handshakes(const char *host, const char *port, const char *sni,
                            const d2k_opts *opt, int *unmeasured)
{
    int i, done = 0;
    for (i = 0; i < opt->repeats; i++) {
        int r = d2k_resp_handshake12(host, port, sni, opt);
        if (r > 0) {
            done++;
        } else if (r < 0) {
            (*unmeasured)++;
        }
    }
    return done;
}

/* neutralSNI — имя для контроля. Домен example.com зарезервирован IANA
 * (RFC 2606) и в списках не встречается; случайная метка спереди убирает
 * попадание в кэши и в состояние коробки. */
void d2k_neutral_sni(char *out, size_t cap)
{
    unsigned i;
    char hex[11];
    unsigned char rnd[10];
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    /* crypto/rand у донора; random() без srandom давал одно и то же имя. */
    if (fd >= 0) {
        while (got < sizeof rnd) {
            ssize_t n = read(fd, rnd + got, sizeof rnd - got);
            if (n <= 0)
                break;
            got += (size_t)n;
        }
        close(fd);
    }
    if (got != sizeof rnd) {
        /* Локальное состояние: глобальный ГСЧ не пересеваем. */
        static unsigned counter;
        struct timespec ts;
        uint64_t x;
        clock_gettime(CLOCK_REALTIME, &ts);
        x = ((uint64_t)ts.tv_nsec << 20) ^ (uint64_t)ts.tv_sec ^
            ((uint64_t)getpid() << 40) ^ ((uint64_t)++counter * 0x9e3779b97f4a7c15ULL);
        x |= 1;
        for (i = 0; i < sizeof rnd; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            rnd[i] = (unsigned char)(x >> 24);
        }
    }
    for (i = 0; i < 10; i++) {
        hex[i] = "0123456789abcdef"[rnd[i] & 0xf];
    }
    hex[10] = '\0';
    snprintf(out, cap, "z%s.example.com", hex);
}

/* Чистое решение по счётчикам. Неизмеренный прогон (локальный предел буфера) не
 * есть ни «дошло», ни «не дошло»: любой такой прогон — НЕ ИЗМЕРЕНО, но не
 * «режут ответ». */
void d2k_resp_decide(int target, int control, int unmeasured, int repeats,
                     d2k_resp_result *res)
{
    res->target = target;
    res->control = control;
    if (unmeasured > 0) {
        res->verdict = D2K_RESP_NOT_APPLICABLE;
        snprintf(res->reason, sizeof(res->reason),
                 "ответ сервера не поместился в локальный предел буфера (64 КБ) в %d прогонах — "
                 "про ответное направление вывода нет", unmeasured);
    } else if (control == 0) {
        res->verdict = D2K_RESP_NOT_APPLICABLE;
        snprintf(res->reason, sizeof(res->reason),
                 "контрольное рукопожатие по TLS 1.2 не завершается — сервер его не поддерживает "
                 "или мешает что-то ещё; про ответное направление вывода нет");
    } else if (target == repeats) {
        res->verdict = D2K_RESP_CLEAR;
        snprintf(res->reason, sizeof(res->reason),
                 "рукопожатие TLS 1.2 доходит до конца — сертификат не режут");
    } else if (target == 0) {
        res->verdict = D2K_RESP_BLOCKED;
        snprintf(res->reason, sizeof(res->reason),
                 "запрос проходит, а рукопожатие не завершается: с нейтральным именем на тот же "
                 "адрес оно завершается каждый раз. Значит режут ОТВЕТ — сертификат в TLS 1.2 "
                 "идёт открытым текстом");
    } else {
        res->verdict = D2K_RESP_FLAKY;
        snprintf(res->reason, sizeof(res->reason),
                 "рукопожатий дошло %d из %d — не воспроизводится", target, repeats);
    }
}

/* ProbeResponse проверяет, не режут ли ОТВЕТ сервера.
 *
 * Зовётся только там, где запрос уже признан проходящим: если режут запрос,
 * про ответ говорить рано. */
void d2k_probe_response(const char *host, const char *port, const char *sni,
                        const d2k_opts *opt, d2k_resp_result *res)
{
    char neutral[64];
    int target, control, unmeasured = 0;

    memset(res, 0, sizeof(*res));
    target = count_handshakes(host, port, sni, opt, &unmeasured);
    /* Контроль ОБЯЗАН быть другим именем на том же адресе. Если бы мы взяли то
     * же самое, молчали бы оба, и «режут ответ» получилось бы из собственной
     * ошибки ввода. */
    d2k_neutral_sni(neutral, sizeof(neutral));
    control = count_handshakes(host, port, neutral, opt, &unmeasured);
    d2k_resp_decide(target, control, unmeasured, opt->repeats, res);
}
