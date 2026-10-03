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
    D2K_HTTPS_UNCONFIRMED,   /* 443 принимает, TLS не завершился */
    D2K_HTTPS_PROBING        /* зонд в работе */
} d2k_https_state;

/* Факты одного зонда → состояние. connect_result: 0 соединился, 1 отказ или
 * недостижимо, 2 тишина/местная ошибка. peer_name: 1 имя в сертификате,
 * 0 чужое, -1 не прочитано. */
#define D2K_HTTPS_CONNECTED 0
#define D2K_HTTPS_REFUSED   1
#define D2K_HTTPS_NO_ANSWER 2
d2k_https_state d2k_https_classify(int connect_result, int tls_ok, int peer_name);
/* Сколько секунд верить ответу. Подтверждённый HTTPS — 6 ч (датапат держит
 * столько же); закрытый 443 и чужое имя — 30 мин; неподтверждённый — 2 мин. */
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
} d2k_httpsprobe_result;

/* Забирает готовые ответы (не больше cap), кладёт их в кэш. */
size_t d2k_httpsprobe_done(d2k_httpsprobe *p, int64_t now_ms,
                           d2k_httpsprobe_result *out, size_t cap);

/* Что известно об имени сейчас (для тестов и журнала). */
d2k_https_state d2k_httpsprobe_state(d2k_httpsprobe *p, const char *host, int64_t now_ms);

#endif /* D2K_HTTPSPROBE_H */
