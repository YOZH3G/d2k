/* d2k_icmpguard.h — ICMP «время жизни истекло» на СОБСТВЕННЫЕ фальшивки.
 *
 * ЗАЧЕМ. Фальшивка с пониженным TTL/hop limit умирает по дороге — в этом её
 * смысл: коробка её видит, сервер нет. Узел, где она умерла, честно отвечает
 * ICMP time-exceeded (ICMPv6 time exceeded), а NAT роутера (conntrack
 * RELATED) переводит его клиенту — по кортежу потока клиента, потому что
 * фальшивка шла в той же записи conntrack. Клиент получает ошибку на пакет,
 * которого он не посылал.
 *
 * Поле 04.10.2026, KN-1811, icmp-rua.pcap: Safari открывает rua.gr по QUIC,
 * план шлёт две фальшивки Initial с TTL 3, третий узел (62.115.145.221)
 * отвечает time-exceeded, и через 35 мс Mac отвечает на Initial/Handshake
 * сервера port-unreachable: Network.framework закрыл подключённый UDP-сокет
 * по ICMP-ошибке. Без плана Safari доходит. Chrome и собственный зонд d2k
 * ICMP не слушают и проходят — поэтому замер этого не видел.
 *
 * ЧТО ДЕЛАЕТ. Датапат запоминает каждую свою посылку с TTL НИЖЕ, чем у
 * исходного пакета потока (это и есть «фальшивка, ограниченная TTL»), и
 * получает из очереди ICMP time-exceeded (тип 11 код 0; ICMPv6 тип 3 код 0),
 * идущие к клиенту (FORWARD) или роутеру (INPUT). Такой ICMP снимается
 * ТОЛЬКО если цитата внутри него — ровно наша посылка:
 *
 *   кортеж (протокол, адреса, порты) — тот, с которым посылка ушла; на
 *     FORWARD обратный NAT уже переписал цитату назад в локальный кортеж
 *     клиента (видно в icmp-rua.pcap на br0), а посылка и уходила с ним:
 *     очередь висит на POSTROUTING до SNAT (d2k_nat.h);
 *   длина IP — та же; IPv4 ID — тот же (если мы его задали: ноль ядро
 *     заменяет своим, raw(7)); слово L4 — то же: у TCP номер
 *     последовательности, у UDP поле длины (сумму не сверяем — её правит
 *     NAT);
 *   TTL в цитате не выше посланного (пакет по дороге только убывает);
 *   запись не старше D2K_ICMPGUARD_KEEP_NS.
 *
 * Настоящий пакет клиента того же потока отличается ID (wire*.c ставит ID
 * клиента + 1) или номером/длиной; traceroute — кортежем. PMTU (frag
 * needed, packet too big), unreachable и всё прочее не судятся вовсе.
 * Сомнение — пропуск: без этой защиты ICMP шёл клиенту, и промах возвращает
 * ровно прежнее поведение, а не новое.
 *
 * ЧЕГО НЕТ. Цитаты во внешнем кортеже (если обратный NAT не сработал — записи
 * conntrack нет — цитата не совпадёт, ICMP пройдёт, как раньше); фрагменты
 * IPv6 и заголовки расширения в цитате (фальшивки их не несут). */
#ifndef D2K_ICMPGUARD_H
#define D2K_ICMPGUARD_H

#include <stddef.h>
#include <stdint.h>

/* Сколько последних фальшивок помнить. Не бюджет поведения, а память кольца:
 * ICMP приходит через RTT до узла (миллисекунды), а за D2K_ICMPGUARD_KEEP_NS
 * роутер шлёт фальшивок на порядки меньше (по 1–4 на новый поток с планом).
 * Вытесненная запись означает прежнее поведение — ICMP идёт клиенту. */
#define D2K_ICMPGUARD_SLOTS 256

/* Сколько помнить посылку. ICMP с узла на пути приходит за RTT до этого узла;
 * отложенные фальшивки плана уходят позже записи на задержки плана (десятки
 * мс). Пять секунд перекрывают и очередь на занятом аплинке, а позже ответ
 * на эту посылку уже не придёт. */
#define D2K_ICMPGUARD_KEEP_NS (UINT64_C(5) * UINT64_C(1000000000))

typedef struct {
    uint64_t at;          /* 0 — пусто */
    uint8_t  family, proto, ttl, have_id;
    uint8_t  src[16], dst[16];
    uint8_t  sport[2], dport[2];
    uint8_t  l4word[4];   /* TCP seq / UDP length (+2 нуля) */
    uint16_t ip_len;      /* IPv4 total length / IPv6 payload length */
    uint16_t ip_id;
} d2k_icmpguard_slot;

typedef struct {
    d2k_icmpguard_slot slot[D2K_ICMPGUARD_SLOTS];
    size_t   next;
    uint64_t noted, dropped;
} d2k_icmpguard;

void d2k_icmpguard_init(d2k_icmpguard *g);

/* Запоминает посылку pkt (готовый IPv4/IPv6-пакет TCP/UDP, как уходит в
 * сырой сокет), если её TTL/hop limit ниже orig_ttl — TTL исходного пакета
 * потока. 1 — запомнена, 0 — не фальшивка с пониженным TTL или не разобрана. */
int d2k_icmpguard_note(d2k_icmpguard *g, const uint8_t *pkt, size_t len,
                       uint8_t orig_ttl, uint64_t now_ns);

/* 1 — pkt есть ICMP/ICMPv6 time-exceeded на запомненную фальшивку: снять
 * (DROP). 0 — всё остальное: пропустить. len — сколько байт есть (цитата
 * может быть обрезана copy_range — судим по тому, что есть). */
int d2k_icmpguard_check(d2k_icmpguard *g, const uint8_t *pkt, size_t len,
                        uint64_t now_ns);

uint64_t d2k_icmpguard_dropped(const d2k_icmpguard *g);
uint64_t d2k_icmpguard_noted(const d2k_icmpguard *g);

#endif
