/* d2k_httpsprobe.h — есть ли у имени HTTPS (задача 51).
 *
 * Датапат узнаёт вставку провайдера в открытый HTTP (datapath/http80.c) и
 * сообщает контроллеру имя и адрес (D2K_EV_HTTP_PORTAL). Контроллер проверяет
 * HTTPS этого имени НА ЭТОМ ЖЕ АДРЕСЕ своим TLS-клиентом: TLS 1.3, при отказе
 * 1.2, SNI = имя, имя обязано стоять в сертификате (SAN листа; цепочку d2k не
 * проверяет — хранилища доверия в d2k нет). Подтверждённое имя уезжает
 * датапату (D2K_CMD_SET_HTTPS), и следующая вставка по нему становится 307 на
 * https. Пока ответа нет — вставка проходит как есть: клиента не задерживаем.
 *
 * Сокет зонда несёт метку PROBE_MARK контроллера: он идёт через очередь, и
 * уже подтверждённый план имени к нему применяется, но новое обнаружение из
 * него не рождается (так же помечены verifier-зонды).
 *
 * Зонд — в своём потоке: замер до 2,5 с не должен останавливать цикл
 * событий. Очередь заданий ограничена; повтор по имени — только когда срок
 * прежнего ответа вышел.
 */
#ifndef D2K_HTTPSPROBE_H
#define D2K_HTTPSPROBE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    D2K_HTTPS_UNKNOWN = 0,   /* не проверяли (или срок вышел) */
    D2K_HTTPS_SERVED,        /* TLS прошёл, имя в сертификате */
    D2K_HTTPS_CLOSED,        /* 443 отказал или недостижим */
    D2K_HTTPS_OTHER_NAME,    /* TLS прошёл, сертификат на другое имя */
    D2K_HTTPS_UNCONFIRMED,   /* не решить: SYN к 443 без ответа, или сервер
                                ответил TLS, а наш клиент не договорился */
    D2K_HTTPS_PROBING,       /* зонд в работе */
    D2K_HTTPS_TLS_BLOCKED    /* 443 принял, а на наш ClientHello — сброс,
                                закрытие, тишина или не-TLS байты: ни одного
                                байта TLS от сервера. Так режет коробка. */
} d2k_https_state;

/* Факты одного зонда → состояние. connect_result: 0 соединился, 1 отказ или
 * недостижимо, 2 тишина/местная ошибка. server_tls: на наш ClientHello пришла
 * запись TLS (рукопожатие или тревога) от сервера. peer_name: 1 имя в листе,
 * 0 чужое, -1 не прочитано. */
#define D2K_HTTPS_CONNECTED 0
#define D2K_HTTPS_REFUSED   1
#define D2K_HTTPS_NO_ANSWER 2
d2k_https_state d2k_https_classify(int connect_result, int server_tls, int tls_ok, int peer_name);
/* Три исхода для вставки провайдера (решение владельца 03.10, ревью I1):
 *   SERVED, TLS_BLOCKED — 307 на https. Сама вставка доказывает блокировку
 *     имени; HTTPS, срезанный той же коробкой, браузер получит через обычный
 *     поиск TLS по своему настоящему трафику (d2kc сам поиск не начинает);
 *   CLOSED, OTHER_NAME — HTTPS у сайта нет: портал проходит как есть;
 *   UNCONFIRMED — не решить: портал как есть, перепроверка скоро. */
int d2k_https_upgrade(d2k_https_state s);
/* Сколько секунд верить ответу (и сколько датапат держит 307):
 *   SERVED 6 ч — HTTPS сайта пропадает редко;
 *   TLS_BLOCKED 1 ч — блокировка — свойство линии и держится долго, но час
 *     даёт заметить, что сайт убрал 443, не дольше часа уводя на тупик;
 *   CLOSED / OTHER_NAME 30 мин — сайт может завести HTTPS;
 *   UNCONFIRMED 2 мин — ответ зависел от случая на линии. */
uint32_t d2k_https_ttl(d2k_https_state s);
const char *d2k_https_state_name(d2k_https_state s);

/* Сам зонд: заменяется в тестах. addr — 4 или 16 байт по family. why —
 * человеческое объяснение для журнала. */
typedef d2k_https_state (*d2k_https_probe_fn)(uint8_t family, const uint8_t *addr,
                                              const char *host, uint32_t mark,
                                              char *why, size_t why_cap);
d2k_https_state d2k_https_probe_real(uint8_t family, const uint8_t *addr, const char *host,
                                     uint32_t mark, char *why, size_t why_cap);
/* Порт зонда: 443; тесты подставляют местный. */
extern uint16_t d2k_https_probe_port;

#define D2K_HTTPSPROBE_NAMES 128
#define D2K_HTTPSPROBE_JOBS  16

typedef struct d2k_httpsprobe d2k_httpsprobe;

d2k_httpsprobe *d2k_httpsprobe_new(uint32_t mark, d2k_https_probe_fn probe);
void d2k_httpsprobe_free(d2k_httpsprobe *p);
/* Становится читаемым, когда готов ответ зонда (d2k_httpsprobe_done). */
int d2k_httpsprobe_wake_fd(const d2k_httpsprobe *p);

/* Датапат увидел вставку по host на адресе addr. answered — он уже ответил
 * 307. Возвращает:
 *   1 — поставлен зонд;
 *   2 — HTTPS подтверждён, а датапат его не знает (перезапуск): *resend_ttl —
 *       сколько секунд осталось, команду надо повторить;
 *   0 — делать нечего (ответ известен и свеж, зонд идёт, очередь полна). */
int d2k_httpsprobe_portal(d2k_httpsprobe *p, const char *host, uint8_t family,
                          const uint8_t *addr, int answered, int64_t now_ms,
                          uint32_t *resend_ttl);

typedef struct {
    char host[256];
    d2k_https_state state;
    uint32_t ttl_s;
    char why[256];
    /* Адрес, на котором проверяли (0 — из кэша на диске, адреса нет). */
    uint8_t family, addr[16];
} d2k_httpsprobe_result;

/* Забирает готовые ответы (не больше cap), кладёт их в кэш. */
size_t d2k_httpsprobe_done(d2k_httpsprobe *p, int64_t now_ms,
                           d2k_httpsprobe_result *out, size_t cap);

/* КЭШ НА ДИСКЕ (ревью I2): после перезапуска первый заход не должен снова
 * видеть портал. Текстовый файл: строка «d2k-https 2 <запись, unix>» (старая «d2k-https 1» читается), затем
 * «<состояние> <срок, unix-секунды> <имя>». Пишется атомарно (временный файл,
 * fsync, rename) — save; PROBING не пишется. load берёт всё, что в файле
 * (сколько вмещает кэш — столько и было записано), пропускает истёкшие и
 * негодные строки, срок по стенным часам режется сроком класса (часы роутера
 * до NTP могут быть в прошлом). В push — имена с 307 и остаток срока, их
 * контроллер отдаёт датапату. 0 — нет файла или прочитан; -1 — файл не наш
 * (кэш не тронут, причина в err). */
int d2k_httpsprobe_save(d2k_httpsprobe *p, const char *path, int64_t now_ms, int64_t wall_s,
                        char *err, size_t err_cap);
int d2k_httpsprobe_load(d2k_httpsprobe *p, const char *path, int64_t now_ms, int64_t wall_s,
                        d2k_httpsprobe_result *push, size_t push_cap, size_t *n_push,
                        size_t *n_loaded, char *err, size_t err_cap);
/* Ответы зондов, которым не хватило места до забора (ревью M5). */
uint64_t d2k_httpsprobe_lost(d2k_httpsprobe *p);

/* Что известно об имени сейчас (для тестов и журнала). */
d2k_https_state d2k_httpsprobe_state(d2k_httpsprobe *p, const char *host, int64_t now_ms);

#endif /* D2K_HTTPSPROBE_H */
