#ifndef D2K_QUIC_ARMS_H
#define D2K_QUIC_ARMS_H
#include "d2k_quicprobe.h"

/* One question of the original askArms. Fragments use explicit donor shapes,
 * never the old midpoint substitute. frag: 0 normal, 1 pos8, 2 reverse pos8,
 * 3 tiny three-fragment overlap, 4 three-fragment overlap. */
typedef struct {
    const char *label;
    const char *addr;
    const uint8_t *blob;
    size_t blob_len;
    int copies, ttl, frag, control;
} d2k_quic_arm_question;
typedef d2k_tally (*d2k_quic_arm_probe_fn)(const d2k_quic_arm_question *, void *, int *);

/* Порог и вердикты этапа данных — d2k_quicprobe.h (D2K_QUIC_ARM_DATA_BYTES). */
typedef struct {
    d2k_quic_arm_data_verdict verdict;
    uint64_t app_bytes;   /* данные ответа на запрос, прошедшие после рукопожатия */
    uint16_t local_port;  /* местный порт соединения — свежая четвёрка */
    char reason[256];
} d2k_quic_arm_data;

/* Вердикт по наблюдениям одного соединения — без сети, ради тестов и одного
 * правила для всех: handshake — рукопожатие дошло до прикладных ключей,
 * app_bytes — данные ответа, fin — сервер закрыл поток ответа. */
d2k_quic_arm_data_verdict d2k_quic_arm_data_judge(int handshake, uint64_t app_bytes, int fin);

/* Данные плеча, прошедшего фильтр: user — из контекста. */
typedef d2k_quic_arm_data (*d2k_quic_arm_data_fn)(const d2k_quic_arm_question *, void *user);

/* Сетевой этап данных (quicprobe.c): d2k_qc с воздействием вопроса перед
 * первым Initial, запрос HTTP/3 к sni. Подменяем в тестах. */
typedef d2k_quic_arm_data (*d2k_quic_arm_data_wire_fn)(const d2k_quic_arm_question *,
    const char *sni, uint16_t port, uint32_t wait_ms, uint32_t mark);
extern d2k_quic_arm_data_wire_fn d2k_quic_arm_data_hook;

typedef struct {
    const char (*pool)[D2K_QUIC_ADDR_LEN];
    size_t n_pool, next;
    int residual;
    d2k_quic_arm_probe_fn probe;
    void *user;
    int marked;
    int (*can_ask)(void *); /* shared Run budget; NULL for unbounded unit oracle */
    void *limit_user;
    /* Этап данных (задача 39). NULL — только фильтр: юнит-оракул порядка
       лестницы. Рабочий путь (d2k_quic_original_measure) ставит его всегда. */
    d2k_quic_arm_data_fn data;
    void *data_user;
    /* Время этапа данных — цена уже заданного вопроса, а не следующих:
       бюджет Run продлевается на него (NULL — не продлевать). */
    void (*spent)(void *limit_user, uint32_t ms);
} d2k_quic_arm_context;

/* Runtime transport for one original askArms question. It receives the SNI
 * and question shape so the wire layer can rebuild a fresh donor Initial for
 * each parallel repeat without changing snapshot-based probes elsewhere.
 * The control question (fragment survival) is called with sni == NULL: the
 * wire layer draws a fresh donor neutralName() for every repeat
 * (arms.go:204-205, probe.go:230-234). */
typedef d2k_tally (*d2k_quic_ask_arm_fn)(const d2k_quic_arm_question *,
    const char *, uint16_t, uint32_t, uint32_t, int *);
extern d2k_quic_ask_arm_fn d2k_quic_ask_arm_hook;

d2k_quic_arm d2k_quic_original_arms(d2k_quic_arm_context *ctx);
/* Immutable instrument data; NULL is not replaced with a similar packet. */
const uint8_t *d2k_quic_original_blob(size_t index, size_t *len, const char **name);
d2k_quic_arm d2k_quic_original_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark);
/* Exact original raw-IP shapes; independent from the legacy midpoint hook. */
typedef d2k_tally (*d2k_quic_fragment_fn)(const char *,uint16_t,int,d2k_hello,
    uint32_t,uint32_t,int,int *);
extern d2k_quic_fragment_fn d2k_quic_fragment_hook;
#endif
