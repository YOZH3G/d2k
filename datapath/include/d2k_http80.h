/* d2k_http80.h — вставка провайдера в открытый HTTP (порт 80), задача 51.
 *
 * Поле 03.10.2026 (ER-Telecom, захват на ppp0): клиент шлёт `GET /`, и через
 * 0,7 мс при RTT сервера ~98 мс приходит `HTTP/1.1 302 Moved Temporarily`,
 * `Location: http://lawfilter.ertelecom.ru…` с FIN — дважды; настоящий сервер
 * не отвечает. Ответ, пришедший раньше, чем сервер физически мог ответить,
 * сервером не послан.
 *
 * Модуль видит первые пакеты HTTP-потока (очередь отдаёт по восемь в каждую
 * сторону) и узнаёт вставку по трём признакам сразу:
 *   1. ответ — 30x с Location на хост блокировки (метки как в
 *      d2k_httpup_portal_location), и этот хост не равен Host запроса;
 *   2. ответ стоит ровно в начале потока сервера (seq = ISN+1 из SYN/ACK) и
 *      подтверждает ровно конец запроса (ack);
 *   3. ответ пришёл раньше половины RTT, замеренного этим же потоком
 *      (SYN → SYN/ACK). Половина — запас на разброс: настоящий ответ не
 *      может прийти быстрее, чем запрос дошёл до сервера и вернулся.
 *
 * Что делать с узнанной вставкой, решает знание об HTTPS имени (таблица,
 * которую наполняет контроллер). HTTPS подтверждён — вместо вставки клиент
 * получает 307 на https://тот же host+path с FIN в том же TCP-потоке (точные
 * seq/ack, суммы пересчитаны), серверу уходит RST, остальные пакеты сервера
 * по потоку снимаются. Не подтверждён или неизвестен — вставка проходит как
 * есть: клиента не задерживаем и тупика не создаём.
 *
 * Модуль переносим: ни сокетов, ни часов, время приходит аргументом.
 */
#ifndef D2K_HTTP80_H
#define D2K_HTTP80_H

#include <stddef.h>
#include <stdint.h>

#define D2K_HTTP80_PASS    0   /* пакет идёт как шёл */
#define D2K_HTTP80_DROP    1   /* снять: копия вставки, её FIN, поздний сервер */
#define D2K_HTTP80_REPLACE 2   /* выпустить вместо пакета out[0..len) */

/* Сколько потоков порта 80 помним одновременно и сколько имён с HTTPS. */
#define D2K_HTTP80_FLOWS 128
#define D2K_HTTP80_NAMES 256
/* Путь запроса длиннее не храним: такой поток не переводим на https. */
#define D2K_HTTP80_TARGET_MAX 1024
/* Поток без движения дольше этого забывается. */
#define D2K_HTTP80_IDLE_NS (60ull * 1000000000ull)

typedef struct d2k_http80 d2k_http80;

typedef struct {
    int action;            /* D2K_HTTP80_* */
    int injection;         /* ЭТОТ пакет — первая узнанная вставка потока */
    int answered;          /* вместо вставки клиент получает 307 */
    size_t len;            /* REPLACE: длина пакета в out */
    size_t rst_len;        /* REPLACE: длина RST к серверу в rst (0 — не собран) */
    uint8_t family;        /* 4 или 6 */
    uint8_t client[16], server[16];
    uint16_t client_port, server_port;   /* хостовый порядок */
    uint64_t rtt_ns;       /* SYN → SYN/ACK этого потока */
    uint64_t reply_ns;     /* запрос → ответ */
    char host[256];        /* Host запроса (без :80) */
    char portal[256];      /* хост из Location вставки */
} d2k_http80_res;

typedef struct {
    uint64_t requests;     /* разобранных запросов GET/HEAD */
    uint64_t injections;   /* узнанных вставок (по потоку один раз) */
    uint64_t answered;     /* из них заменено на 307 */
    uint64_t dropped;      /* снятых пакетов сервера после замены */
    uint64_t evicted;      /* потоков, вытесненных из полной таблицы */
} d2k_http80_stats;

d2k_http80 *d2k_http80_new(void);
void d2k_http80_free(d2k_http80 *h);

/* Имя, у которого HTTPS подтверждён, до expires_ns (монотонные часы).
 * expires_ns == 0 убирает имя. Сравнение без учёта регистра, точка в конце
 * не значима. 0 — принято, -1 — имя негодно. Полная таблица вытесняет
 * запись с самым ранним сроком. */
int d2k_http80_set_https(d2k_http80 *h, const char *name, size_t len, uint64_t expires_ns);
int d2k_http80_https(const d2k_http80 *h, const char *host, uint64_t now_ns);

/* Один пакет из очереди (IPv4/IPv6, целиком, с заголовком IP). Решение и
 * подробности — в r. out/rst — буферы для пакета-замены и RST к серверу. */
void d2k_http80_packet(d2k_http80 *h, const uint8_t *pkt, size_t len, uint64_t now_ns,
                       uint8_t *out, size_t out_cap, uint8_t *rst, size_t rst_cap,
                       d2k_http80_res *r);

d2k_http80_stats d2k_http80_get_stats(const d2k_http80 *h);

#endif /* D2K_HTTP80_H */
