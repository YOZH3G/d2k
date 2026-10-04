/* d2k_ctq.h — счётчики ОДНОГО потока conntrack по его кортежу (ctnetlink).
 *
 * Зачем (задача 50, раунд 3). Детектор «QUIC замолчал после рукопожатия»
 * смотрит на счётчики пакетов потока: прямой растёт, обратный стоит. Очередь
 * видит у UDP лишь первые 8 пакетов в каждую сторону, так что счётчики — из
 * conntrack. Раунд 2 читал для этого /proc/net/nf_conntrack целиком раз в
 * секунду прямо в цикле очереди: O(всей таблицы), на 10–30 тысячах записей —
 * сотни миллисекунд, пока очередь не разбирается. Здесь — запрос ЯДРУ по
 * кортежу (IPCTNL_MSG_CT_GET с CTA_TUPLE_ORIG): поиск в хэше, O(1) на поток,
 * O(наблюдаемых потоков) на обход.
 *
 * НЕ ЖДАТЬ НИКОГДА. Ядро отвечает на GET синхронно, внутри sendmsg: к
 * возврату send ответ уже лежит в сокете. Поэтому чтение — MSG_DONTWAIT без
 * опроса: ответа нет — значит, ничего не знаем, и подозрения нет (fail open).
 * Цикл очереди этим вызовом не задерживается ни при каком поведении ядра.
 *
 * Проводной формат собирается по явным смещениям, как в d2k_nl.h, и потому
 * собирается и проверяется на любой машине. Сокет netlink — только Linux.
 *
 * Константы сверены с linux/netfilter/nfnetlink.h и
 * linux/netfilter/nfnetlink_conntrack.h. */
#ifndef D2K_CTQ_H
#define D2K_CTQ_H

#include <stddef.h>
#include <stdint.h>

#define D2K_NFNL_SUBSYS_CTNETLINK 1
#define D2K_IPCTNL_MSG_CT_NEW     0
#define D2K_IPCTNL_MSG_CT_GET     1

#define D2K_CTA_TUPLE_ORIG        1
#define D2K_CTA_COUNTERS_ORIG     9
#define D2K_CTA_COUNTERS_REPLY    10
#define D2K_CTA_TUPLE_IP          1
#define D2K_CTA_TUPLE_PROTO       2
#define D2K_CTA_IP_V4_SRC         1
#define D2K_CTA_IP_V4_DST         2
#define D2K_CTA_IP_V6_SRC         3
#define D2K_CTA_IP_V6_DST         4
#define D2K_CTA_PROTO_NUM         1
#define D2K_CTA_PROTO_SRC_PORT    2
#define D2K_CTA_PROTO_DST_PORT    3
#define D2K_CTA_COUNTERS_PACKETS  1
#define D2K_CTA_COUNTERS_BYTES    2
#define D2K_CTA_COUNTERS32_PACKETS 3
#define D2K_NLA_F_NESTED          0x8000
/* Состояние TCP у conntrack (задача 56): CTA_PROTOINFO → CTA_PROTOINFO_TCP →
   CTA_PROTOINFO_TCP_STATE, u8; значения — enum tcp_conntrack ядра. */
#define D2K_CTA_PROTOINFO         4
#define D2K_CTA_PROTOINFO_TCP     1
#define D2K_CTA_PROTOINFO_TCP_STATE 1
#define D2K_CT_TCP_ESTABLISHED    3

/* Кортеж прямого направления: адреса 4 или 16 байт по family, порты в
   сетевом порядке (как в пакете). */
typedef struct {
    uint8_t family;      /* 4 или 6 */
    uint8_t proto;       /* 6 или 17 */
    uint8_t src[16], dst[16];
    uint8_t sport_be[2], dport_be[2];
} d2k_ct_tuple;

/* Что ядро сказало о потоке. Состояние TCP есть не всегда (UDP, старое
   ядро): без него «соединение ещё установлено» не доказано. */
typedef struct {
    uint64_t orig_pkts, reply_pkts;
    uint8_t  tcp_state;        /* enum tcp_conntrack, если tcp_state_known */
    uint8_t  tcp_state_known;
} d2k_ct_info;

/* Запрос CT_GET по кортежу. Длина сообщения или 0, если не поместилось. */
size_t d2k_ct_get_req(uint8_t *o, size_t cap, uint32_t seq, const d2k_ct_tuple *t);

/* Разбор ответа на запрос seq. 0 — счётчики есть; 1 — ядро ответило ошибкой
   (записи нет: -ENOENT); 2 — запись без счётчиков (accounting выключен);
   -1 — не тот seq или мусор. */
int d2k_ct_counters_parse(const uint8_t *buf, size_t len, uint32_t seq,
                          uint64_t *orig_pkts, uint64_t *reply_pkts);

/* То же, со состоянием TCP (d2k_ct_info). Коды возврата — как у
   d2k_ct_counters_parse. */
int d2k_ct_info_parse(const uint8_t *buf, size_t len, uint32_t seq, d2k_ct_info *out);

/* Спросить по уже открытому сокету fd: послать и забрать ответ БЕЗ ожидания.
   0 — счётчики; 1 — ошибка ядра (записи нет); 2 — запись без счётчиков
   (accounting выключен); -1 — ответа нет. Всё, кроме 0, — «не знаем». Чужие
   и устаревшие ответы в сокете вычитываются и отбрасываются. */
int d2k_ct_query_fd(int fd, uint32_t seq, const d2k_ct_tuple *t,
                    uint64_t *orig_pkts, uint64_t *reply_pkts);

/* То же с d2k_ct_info: счётчики и состояние TCP одним запросом. */
int d2k_ct_query_info_fd(int fd, uint32_t seq, const d2k_ct_tuple *t, d2k_ct_info *out);

/* ПРОБА ДОСТУПНОСТИ (раунд 4, N2). Где nf_conntrack_netlink не загружен, ядро
   на каждый GET синхронно зовёт request_module внутри sendmsg — модпроб на
   пакетном пути. Поэтому при старте (и только на обновлении правил/маршрутов,
   не на пакетах) задаётся один GET несуществующей записи: ENOENT — ctnetlink
   есть (1); любая другая ошибка или молчание wait_ms — нет (0), и запросов по
   потокам d2kd не шлёт вовсе. */
int d2k_ct_probe_fd(int fd, uint32_t seq, int wait_ms);

/* Сокет NETLINK_NETFILTER, неблокирующий. -1 — не Linux или ядро не дало. */
int d2k_ct_open(void);

#endif /* D2K_CTQ_H */
