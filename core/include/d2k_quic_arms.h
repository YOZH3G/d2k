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
    /* Задача 40. split: 1 — ClientHello нашего Initial разрезан на два кадра
       CRYPTO, хвост первым (d2k_quic_initial_split_crypto); blob при нём
       пуст. benign: blob — безобидная датаграмма вопроса «остаточное
       разрешение» (D2K_QUIC_BENIGN), а не приманка перебора. */
    int split, benign;
} d2k_quic_arm_question;

/* БЕЗОБИДНАЯ ДАТАГРАММА ВОПРОСА «ОСТАТОЧНОЕ РАЗРЕШЕНИЕ» (задача 40).
 *
 * Heitmann et al., FOCI 2026: для части имён (discord.com, *.googlevideo.com,
 * play.google.com …) коробка не трогает Initial, если по той же четвёрке
 * раньше ушли незапрещённые данные. Вопрос: одна такая датаграмма, затем наш
 * Initial на той же свежей четвёрке.
 *
 * Форма — 16 нулевых байт, и выбрана она по трём причинам:
 *   - коробке её не разобрать как Initial: первый байт 0x00 — короткий
 *     заголовок с погашенным фиксированным битом, 16 байт меньше любого
 *     Initial (RFC 9000 §14.1: не меньше 1200);
 *   - серверу отвечать на неё нечем: пакет с нулевым фиксированным битом
 *     отбрасывается (RFC 9000 §17.3.1), а для сброса без состояния он мал
 *     (§10.3) — ответ на сокете вопроса остаётся только ответом на наш
 *     Initial; случайные байты с первым 0xC0.. выглядели бы длинным
 *     заголовком чужой версии и могли бы вызвать Version Negotiation;
 *   - это те же байты, что «мусор» оригинала (questions.go:97) и приманка
 *     0x00…0 askArms, и датапат их уже исполняет (fake place=before): что
 *     мерили, то и ставится, без новой грамматики плана.
 * Копия одна: вопрос ровно про «первой ушла безобидная датаграмма». */
#define D2K_QUIC_BENIGN_LEN 16
extern const uint8_t d2k_quic_benign[D2K_QUIC_BENIGN_LEN];

/* Сколько опросов могут стоить два вопроса стратегии: каждый — до одного
   повтора, пока исход не решающий (правило задачи 35). Бюджет Run выводится
   и из этого числа. */
#define D2K_QUIC_STRATEGY_ASKS_MAX 4u
typedef d2k_tally (*d2k_quic_arm_probe_fn)(const d2k_quic_arm_question *, void *, int *);

/* Порог и вердикты этапа данных — d2k_quicprobe.h (D2K_QUIC_ARM_DATA_BYTES). */
typedef struct {
    d2k_quic_arm_data_verdict verdict;
    uint64_t app_bytes;   /* данные ответа на запрос, прошедшие после рукопожатия */
    uint16_t local_port;  /* местный порт соединения — свежая четвёрка */
    char note[256];      /* приветствие и путь этапа (в трассу шага) */
    char reason[256];
} d2k_quic_arm_data;

/* d2k_quic_arm_data_judge — d2k_quicprobe.h (одно правило с verify.c). */

/* Данные плеча, прошедшего фильтр: user — из контекста. */
typedef d2k_quic_arm_data (*d2k_quic_arm_data_fn)(const d2k_quic_arm_question *, void *user);

/* Сетевой этап данных (quicprobe.c): d2k_qc с воздействием вопроса перед
 * первым Initial, запрос HTTP/3 к sni по пути path (NULL или пусто — «/»;
 * планировщик подставляет известный большой ресурс цели). Подменяем в тестах. */
typedef d2k_quic_arm_data (*d2k_quic_arm_data_wire_fn)(const d2k_quic_arm_question *,
    const char *sni, const char *path, uint16_t port, uint32_t wait_ms, uint32_t mark);
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
    /* Путь запроса этапа данных (d2k_quic_arm.probe_path); NULL — «/». */
    const char *path;
    /* Задача 40: вопрос «остаточное разрешение» уже задан в этом поиске (до
       решающего ответа или до предела повторов) — запасной перебор не задаёт
       его второй раз под видом приманки 0x00…0 ×1 (тот же вопрос). */
    int benign_answered;
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

/* СТРАТЕГИЯ ИЗ ОТВЕТОВ (задача 40) — рабочий путь подбора QUIC.
 *
 * Два вопроса, каждый — фильтр (ответ сервера, привязанный к нашему Initial,
 * 3/3) и этап данных (d2k_quic_arm_data_judge), на свежей четвёрке, по тому
 * же правилу адресов, что у askArms:
 *   1. остаточное разрешение: D2K_QUIC_BENIGN первой, затем Initial.
 *      Да → kind D2K_QA_BLOB, байты D2K_QUIC_BENIGN, copies 1,
 *      strategy D2K_QS_CLEARANCE; дальше ничего не спрашивается.
 *   2. разрез ClientHello на два кадра CRYPTO. Да → kind D2K_QA_SPLIT,
 *      strategy D2K_QS_SPLIT.
 * Оба решающих «нет» → D2K_QA_NOT_FOUND, «обход по QUIC не найден»: приманки
 * не перебираются (браузер уйдёт на TCP). Решающий исход — 3/3 с итогом
 * этапа данных либо 0/3; иначе (1–2 из 3, не отправилось, этап данных не
 * состоялся) вопрос повторяется ОДИН раз. Остался без решающего ответа хотя
 * бы один вопрос — запасной путь: d2k_quic_original_arms (strategy
 * D2K_QS_LADDER), его трасса дописывается следом. clearance/split_crypto
 * несут ответы (D2K_PROP_*). Метка не подтверждена — D2K_QA_FLAKY. */
d2k_quic_arm d2k_quic_strategy_arms(d2k_quic_arm_context *ctx);
/* Рабочий адаптер стратегии (props.c): те же провод и этап данных, что у
 * d2k_quic_original_measure; запасной перебор — его же лестница. */
d2k_quic_arm d2k_quic_strategy_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark);
/* Immutable instrument data; NULL is not replaced with a similar packet. */
const uint8_t *d2k_quic_original_blob(size_t index, size_t *len, const char **name);
d2k_quic_arm d2k_quic_original_measure(d2k_quic_arm_context *ctx, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t wait_ms, uint32_t mark);
/* Exact original raw-IP shapes; independent from the legacy midpoint hook. */
typedef d2k_tally (*d2k_quic_fragment_fn)(const char *,uint16_t,int,d2k_hello,
    uint32_t,uint32_t,int,int *);
extern d2k_quic_fragment_fn d2k_quic_fragment_hook;
#endif
