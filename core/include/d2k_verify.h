/* d2k_verify.h — подтверждение работоспособности без ложного успеха.
 *
 * ПОЧЕМУ ПРЕЖНЕГО ПОРОГА НЕ ХВАТАЛО. Успехом считался внешний тип записи TLS
 * 23 («прикладные данные») в событии обмена. В TLS 1.3 это не признак работы
 * приложения: наружу типом 23 едет ВЕСЬ второй полёт рукопожатия — смена
 * шифра, расширения, сертификат, подпись, Finished (RFC 8446 §5.2), а
 * настоящий тип записи лежит ВНУТРИ шифротекста и наблюдателю на проводе не
 * виден. «Сервер что-то ответил» читалось как «приложение работает», и
 * кандидат, который довёл дело только до ответа коробки, записывался в
 * каталог как рабочий.
 *
 * ПОЧЕМУ ПОВТОР СНЯТОГО ПРИВЕТСТВИЯ НЕ ГОДИТСЯ В ДОКАЗАТЕЛЬСТВА. Приветствие
 * чужой сессии (§4: измерительный прибор) отправить можно, а завершить по
 * нему рукопожатие нельзя никогда: закрытого ключа того клиента у нас нет, и
 * дальше чужого второго полёта дело не пойдёт по устройству, а не по
 * невезению. Поэтому доказательство ведёт СВОЁ рукопожатие своим ключом
 * (core/tls13.c) и доводит обмен до настоящего ответа приложения.
 *
 * ПЯТЬ РЕЗУЛЬТАТОВ, КОТОРЫЕ НЕЛЬЗЯ СЛИВАТЬ. Каждый следующий — строго больше
 * предыдущего, и ни один не подменяет соседа:
 *
 *   не измерено  — обращения не было вовсе, про линию не сказано НИЧЕГО
 *                  (§2.4: это не «нет», и ноль не превращается в диагноз);
 *   транспорт    — TCP встал, дальше не пошло. Сюда попадает и сервер,
 *                  ответивший «HTTP/1.1 200 OK» открытым текстом: ответ был,
 *                  доказательства нет;
 *   рукопожатие  — НАШЕ рукопожатие TLS 1.3 завершено нашим ключом, но
 *                  приложение молчит;
 *   приложение   — получен конечный HTTP-ответ вместе с полным телом; одноимённые
 *                  редиректы проверяются на той же TLS-сессии;
 *   challenge    — Cloudflare явно прислал cf-mitigated: challenge. Ответ
 *                  дошёл до HTTP, но это не доказательство полезного обхода.
 *
 * Уровень «приложение» доказывает завершённый HTTP-обмен внутри собственной
 * сессии. Подлинность сервера и доступность страницы после переходов на другое
 * имя НЕ проверены.
 * В частности, 403 остаётся HTTP-ответом, а не доказательством снятой блокировки.
 *
 * Сокет обращения остаётся ОТКРЫТЫМ до d2k_verify_close — не удобство, а
 * условие того, что измерение вообще что-то измеряет: датапат по FIN удаляет
 * ячейку потока (datapath/session.c), и событие применения плана становится
 * не с чем связать. Это уже стоило проекту дня отладки — см.
 * docs/field/2026-09-11-first-c-ask.md и doc-комментарий d2k_props_contact.
 */
#ifndef D2K_VERIFY_H
#define D2K_VERIFY_H

#include <stdint.h>
#include "d2k_resource.h"
#include "d2k_http_reply.h"
#include "d2k_tls13core.h"

typedef enum {
    D2K_VER_NOT_MEASURED = 0, /* обращение не состоялось — про линию не сказано ничего */
    D2K_VER_TRANSPORT,        /* TCP встал, рукопожатие не дошло до конца */
    D2K_VER_HANDSHAKE,        /* рукопожатие завершено, прикладного ответа нет */
    D2K_VER_APPLICATION,      /* полный HTTP-ответ, включая HTTPS redirect другой цели */
    D2K_VER_CHALLENGE,        /* Cloudflare cf-mitigated: challenge; не успех обхода */
    D2K_VER_BLOCKPAGE,        /* явная сигнатура страницы блокировки */
    D2K_VER_DENIED            /* HTTP 451: юридический отказ, не диагноз DPI */
} d2k_ver_level;

typedef struct {
    d2k_ver_level level;
    int      status;        /* код состояния HTTP, 0 — не разобран */
    uint64_t body_bytes;    /* прочитанное тело HTTP, без chunk framing */
    uint64_t body_expected; /* Content-Length либо измеренное число chunk-байт */
    int      body_complete; /* тело полностью прочитано по HTTP framing */
    int      body_has_length; /* получен однозначный Content-Length */
    int      body_chunked;   /* применён Transfer-Encoding: chunked */
    int      body_framing_valid; /* разбор framing однозначен, даже если тело оборвалось */
    int      body_encoding;  /* 0 identity/нет, 1 gzip, 2 другое/несколько */
    char     location[512];  /* Location ответа; другая цель не посещается этим зондом */
    int      cloudflare_challenge; /* получен cf-mitigated: challenge */
    d2k_http_outcome http_outcome;
    char     http_evidence[64];
    uint16_t local_port;    /* местный порт обращения — ключ потока для привязки события */
    uint8_t  local_ip4[4];
    uint8_t  family;
    uint8_t  local_addr[16];
    int      fd;            /* сокет держится ОТКРЫТЫМ до d2k_verify_close */
    char     reason[200];   /* человеческая причина достигнутого уровня, всегда заполнена */
    /* Совпало ли имя, которым представился сервер, с тем, что мы спросили:
       1 — да, 0 — НЕТ, -1 — сказать нечего. Значимо только начиная с уровня
       рукопожатия: до него сертификата не бывает.

       Это НЕ подлинность (цепочка не строится) и НЕ доказательство заглушки.
       Для обычного TLS несовпадение диагностическое; ECH требует отдельного
       строгого подтверждения имени origin и принятия ECH. */
    int      name_ok;
    /* Зонд НЕ УМЕЕТ такой транспорт — и не научится сменой кандидата.
     *
     * Отличается от обычного «не измерено» (нет TCP, молчание) тем, что
     * повторять бессмысленно: следующий кандидат получит тот же ответ, и
     * весь бюджет зондов уйдёт на установку планов, которые никто не
     * проверит. Сегодня так отвечает QUIC: вопросник для него есть
     * (quicprobe умеет спрашивать Initial), а зонда, доводящего прикладной
     * обмен до конца, нет.
     *
     * Это утверждение о НАС, а не о коробке и не о кандидате: в каталог по
     * нему не идёт ничего, ни положительного, ни отрицательного (§10). */
    int      unsupported;
    int      ech_accepted; /* own ECH acceptance, not extension presence/GREASE */
    /* Зонд говорил ALPN клиента, и этот протокол — НЕ HTTP (задача 37, F3).
       Тогда доказательство на проводе — завершённое рукопожатие TLS (level
       D2K_VER_HANDSHAKE: ServerHello и проверенный Finished сервера), а
       прикладной уровень НЕ ИЗМЕРЕН: HTTP-запрос на чужом языке ничего не
       доказал бы. Это не D2K_VER_APPLICATION и за него не выдаётся. */
    int      handshake_proof;
    d2k_resource resources[D2K_RESOURCE_COUNT];
    size_t n_resources; /* hints only, from a complete anonymous HTML response */
} d2k_ver_result;

/* Same verifier and protocol, with a public stylesheet witness instead of /.
 * NULL preserves /. No arbitrary URI, credentials, query strings or redirects
 * to a different host are accepted. mark must be set before connect(). */
d2k_ver_result d2k_verify_probe_path_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12,
    int encoding, uint32_t mark, const char *path);

/* Одно обращение к цели со СВОИМ рукопожатием и настоящим запросом.
 *
 * ip/port — куда идти, sni — имя, которое предъявляем в приветствии и в
 * заголовке Host (пустое — берётся адрес). deadline_ms — потолок отдельно на
 * рукопожатие и отдельно на ожидание ответа: страховка от молчания, а не
 * общий бюджет.
 *
 * Обращение идёт НЕПОМЕЧЕННЫМ: помеченный пакет уходит мимо NFQUEUE первым
 * правилом цепочки (files/S99d2k), поставленный план к нему не применится, и
 * зонд мерил бы линию БЕЗ обхода, считая, что мерит с обходом.
 *
 * Блокирует вызывающий поток на время обмена — значит, зовётся только из
 * рабочего потока: цикл d2kc не блокируется никогда.
 *
 * hello_wire — длина приветствия, СНЯТОГО С КЛИЕНТА, до которой зонд добивает
 * своё (0 — не добивать). Без неё измерение идёт в другом контексте, чем
 * работа человека: см. d2k_tls_connect. */
d2k_ver_result d2k_verify_probe(const char *ip, uint16_t port, const char *sni,
                                int deadline_ms, size_t hello_wire);

/* То же, но на УЖЕ ЗАНЯТОМ сокете. Нужно испытанию кандидата: его план
 * ставится только для местного порта зонда, а порт обязан быть известен ДО
 * подключения (d2k_props_bind, d2k_link_set_name_probe). Меньше нуля —
 * создать свой сокет, тогда это в точности d2k_verify_probe. */
d2k_ver_result d2k_verify_probe_on(int use_fd, const char *ip, uint16_t port,
                                   const char *sni, int deadline_ms, size_t hello_wire);

/* Зонд TLS 1.3 с ALPN КЛИЕНТА (alpn_list — protocol_name_list как на проводе,
 * alpn_len 0 — без ALPN, как у клиента без него) для протокола, который не
 * HTTP. Ведёт рукопожатие до проверенного Finished сервера и останавливается:
 * HTTP-запроса нет. Успех — level D2K_VER_HANDSHAKE и handshake_proof = 1;
 * прикладной уровень не измерен (см. handshake_proof). Сокет — как у
 * d2k_verify_probe_on. */
d2k_ver_result d2k_verify_probe_alpn_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms, size_t hello_wire,
                                        const uint8_t *alpn_list, size_t alpn_len);

/* То же, но рукопожатием TLS 1.2 — для клиента СТАРОЙ формы.
 *
 * Подтверждать его обход современным рукопожатием значит записывать план под
 * форму, которой у этого клиента нет: по ключу формы такой план ему не
 * достанется вовсе (MVP_CHECKLIST, пункт 3). Приветствие берётся из профиля,
 * а не из живого снимка — почему, сказано у самой функции.
 *
 * hello_wire — та же надобность, что у зонда 1.3: план, чьи куски помещаются
 * в посылку на коротком приветствии, на длинном не помещается вовсе. */
d2k_ver_result d2k_verify_probe12_on(int use_fd, const char *ip, uint16_t port,
                                     const char *sni, int deadline_ms,
                                     size_t hello_wire);

/* RX-volume candidates must prove the previously truncated identity body,
 * not the compressed control that already worked without a candidate. */
d2k_ver_result d2k_verify_probe_identity_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12);
d2k_ver_result d2k_verify_probe_gzip_on(int use_fd, const char *ip, uint16_t port,
    const char *sni, int deadline_ms, size_t hello_wire, int tls12);

/* Базовое измерение полноты ответа на сокете, который обходит активные планы
 * через SO_MARK. encoding: 0 — identity, 1 — gzip; tls12 выбирает ровно ту же
 * форму клиента, что и живой поток. Используется парным измерителем объёма,
 * не кандидатом: проверочные зонды, наоборот, обязаны проходить через план. */
d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
                                         const char *sni, int deadline_ms,
                                         size_t hello_wire, int tls12,
                                         int encoding, uint32_t mark);

/* ТО ЖЕ САМОЕ, НО ПО QUIC. Уровни и их смысл не меняются ни на йоту:
 * TRANSPORT — датаграммы уходят, ответа нет; HANDSHAKE — рукопожатие
 * завершено, приложение молчит; APPLICATION — пришёл код ответа HTTP/3.
 * Послаблений для QUIC нет и быть не может: доказательством считается
 * прикладной обмен, а не «сервер что-то прислал».
 *
 * hello_wire — длина приветствия, снятого с клиента, до которой зонд добивает
 * своё; смысл тот же, что у d2k_verify_probe. */
d2k_ver_result d2k_verify_probe_quic(const char *ip, uint16_t port, const char *sni,
                                     int deadline_ms, size_t hello_wire);

/* То же на УЖЕ ЗАНЯТОМ сокете UDP — испытанию кандидата по QUIC, чтобы его
 * план достался только потоку зонда (d2k_props_bind_udp). */
d2k_ver_result d2k_verify_probe_quic_on(int use_fd, const char *ip, uint16_t port,
                                        const char *sni, int deadline_ms,
                                        size_t hello_wire);
/* То же, но запрос HTTP/3 — по пути path (известный большой ресурс цели);
 * NULL или пусто — «/». Успех — тот же, что у этапа данных плеча: ответ
 * целиком без дыр или не меньше D2K_QUIC_ARM_DATA_BYTES. */
d2k_ver_result d2k_verify_probe_quic_path_on(int use_fd, const char *ip, uint16_t port,
                                             const char *sni, int deadline_ms,
                                             size_t hello_wire, const char *path);

/* Закрывает сокет обращения и обнуляет fd. Безопасна на любом результате, в
 * том числе на том, где обращения не было. */
void d2k_verify_close(d2k_ver_result *r);

/* Explicit origin witness: outer SNI is config.public_name, HTTP authority
 * and certificate-name observation are origin. Never follows another host. */
d2k_ver_result d2k_verify_probe_ech_on(int use_fd, const char *ip, uint16_t port,
    const char *origin, const d2k_ech_config *config, int deadline_ms,
    size_t hello_wire, uint32_t mark, const char *path);
/* Bounded HTTPS-RR lookup for a known origin; does not invent origin names
 * from a shared IP, install DNS overrides, or treat missing records as clear. */
int d2k_ech_resolve(const char *origin, uint32_t mark, d2k_ech_config *config);
/* Resolve a fresh config, but only for the caller's explicit known witness.
 * An unmatched public name cannot verify the target's candidate plan. */
d2k_ver_result d2k_verify_probe_ech_origin_on(int use_fd, const char *ip,
    uint16_t port, const char *outer_name, const char *origin, int deadline_ms,
    size_t hello_wire, uint32_t dns_mark, const char *path);

#endif /* D2K_VERIFY_H */
