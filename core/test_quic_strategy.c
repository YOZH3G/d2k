/* test_quic_strategy.c — стратегия QUIC из ответов замера (задача 40).
 *
 * Два вопроса раньше перебора приманок, на подменённых ответах:
 *   1. «остаточное разрешение» — безобидная датаграмма первой на той же
 *      четвёрке, затем наш Initial; да → план «одна безобидная датаграмма
 *      перед Initial», перебора нет;
 *   2. разрез ClientHello на кадры CRYPTO; да → план разреза.
 * Оба «нет» и фрагменты не прошли → перебор приманок askArms без уже
 * заданных вопросов (поле 04.10, rutracker.org: «нет» на оба вопроса не
 * значит, что приманки бесполезны). Перебор приманок (askArms) — и когда
 * ответ не получен (неизмеримо). Вопрос
 * повторяется один раз, пока исход не решающий (правило задачи 35).
 */
#include <stdio.h>
#include <string.h>
#include "d2k_quic_arms.h"

static int fails, calls, data_calls;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); fails++; } } while (0)

/* Ответы по классу вопроса: 'Y' 3/3 и данные прошли, 'C' 3/3 и поток
   оборван, 'N' 0/3, 'M' 1/3, 'E' не отправилось, 'R' 3/3 и этап данных не
   состоялся. Строка — по символу на повтор вопроса. */
static const char *ans_clear, *ans_split;
static int i_clear, i_split, ladder_calls, ladder_pass, marked_ok;
/* Круг 1: форма фрагментации, которая проходит (0 — фрагменты не доживают). */
static int frag_ok_shape;
/* Поле 02.10 rutracker.org: из приманок прошла только fake_default_quic ×11. */
static int fake_ok_blob = -1, fake_ok_copies;
static d2k_quic_arm_question seen[64];

static char next_answer(const d2k_quic_arm_question *q) {
    if (q->split) return ans_split[i_split] ? ans_split[i_split++] : 'N';
    if (q->blob_len == D2K_QUIC_BENIGN_LEN && q->copies == 1 && !q->ttl && !q->frag &&
        !q->control && q->benign) return ans_clear[i_clear] ? ans_clear[i_clear++] : 'N';
    return 0;
}

static char last;
static d2k_tally probe(const d2k_quic_arm_question *q, void *u, int *sent) {
    (void)u;
    if (calls < 64) seen[calls] = *q;
    calls++;
    d2k_tally t = {0};
    t.marked = marked_ok;
    char a = next_answer(q);
    last = a;
    if (!a) {
        ladder_calls++;
        *sent = 3;
        size_t fl = 0;
        const uint8_t *fb = fake_ok_blob >= 0 ?
            d2k_quic_original_blob((size_t)fake_ok_blob, &fl, NULL) : NULL;
        if ((ladder_pass && !q->control && !q->frag) ||
            (frag_ok_shape && (q->control || q->frag == frag_ok_shape)) ||
            (fb && q->blob == fb && q->copies == fake_ok_copies && !q->ttl && !q->frag)) t.pass = 3;
        else t.fail = 3;
        return t;
    }
    if (a == 'E') { *sent = 0; t.err = t.fail = 3; return t; }
    *sent = 3;
    if (a == 'Y' || a == 'C' || a == 'R') t.pass = 3;
    else if (a == 'M') { t.pass = 1; t.fail = 2; }
    else t.fail = 3;
    return t;
}

static d2k_quic_arm_data data(const d2k_quic_arm_question *q, void *u) {
    (void)q; (void)u;
    data_calls++;
    d2k_quic_arm_data d;
    memset(&d, 0, sizeof d);
    d.verdict = last == 'C' ? D2K_QAD_CUT : last == 'R' ? D2K_QAD_NOT_RUN : D2K_QAD_PASS;
    d.app_bytes = d.verdict == D2K_QAD_PASS ? D2K_QUIC_ARM_DATA_BYTES : 0;
    return d;
}

static char pool[3][D2K_QUIC_ADDR_LEN] = {"127.0.0.1", "127.0.0.2", "127.0.0.3"};

static d2k_quic_arm run(const char *c, const char *s, int residual, size_t n_pool) {
    ans_clear = c; ans_split = s; i_clear = i_split = 0;
    calls = data_calls = ladder_calls = 0;
    d2k_quic_arm_context ctx = {.pool = pool, .n_pool = n_pool, .next = 1, .residual = residual,
                                .probe = probe, .marked = 1, .data = data};
    return d2k_quic_strategy_arms(&ctx);
}

int main(void) {
    static const uint8_t zero16[16];
    marked_ok = 1;

    /* 1. Остаточное разрешение есть: одна безобидная датаграмма, перебора нет. */
    d2k_quic_arm r = run("Y", "", 0, 1);
    CHECK(r.kind == D2K_QA_BLOB && r.strategy == D2K_QS_CLEARANCE && r.original);
    CHECK(r.len == D2K_QUIC_BENIGN_LEN && !memcmp(r.bytes, zero16, 16) && r.copies == 1 && !r.ttl);
    CHECK(r.clearance == D2K_PROP_YES && r.split_crypto == D2K_PROP_UNKNOWN);
    CHECK(calls == 1 && r.probes == 3 && data_calls == 1 && ladder_calls == 0 && !r.incomplete);
    CHECK(seen[0].benign && seen[0].blob_len == 16 && !strcmp(seen[0].addr, pool[0]));
    CHECK(r.n_trace == 1 && r.trace[0].data == D2K_QAD_PASS);

    /* 2. Разрешения нет, разрез CRYPTO проходит. */
    r = run("N", "Y", 0, 1);
    CHECK(r.kind == D2K_QA_SPLIT && r.strategy == D2K_QS_SPLIT && r.len == 0);
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_YES);
    CHECK(calls == 2 && r.probes == 6 && data_calls == 1 && ladder_calls == 0);
    CHECK(seen[1].split == 1 && !seen[1].blob_len);

    /* 3. Оба «нет», фрагменты не доживают — это ПОЛЕ 04.10, rutracker.org
          (06:02:30: 0/3, 0/3, 0/3 — «плечо не нашлось за 9 опытов», браузер
          ушёл на TCP). Эти ответы не говорят о приманках ничего: на том же
          имени 02.10 21:39 fake_default_quic ×11 прошла 3/3, её план
          389a3920 — 4/4 полных ответа (task-55-facts §2). Дальше —
          перебор askArms, но уже заданные вопросы (0x00…0 ×1 и выживание
          фрагментов) он не повторяет. */
    fake_ok_blob = 3; fake_ok_copies = 11;
    r = run("N", "N", 0, 1);
    CHECK(r.strategy == D2K_QS_LADDER && r.kind == D2K_QA_COPIES && !r.incomplete);
    CHECK(r.copies == 11 && !r.ttl && !strcmp(r.blob_name, "fake_default_quic"));
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_NO);
    CHECK(r.frag_survives == D2K_PROP_NO && !r.frag_kind);
    /* 3 вопроса стратегии; приманки ×1 без 0x00…0 (4), копии quic5 ×6/×11 и
       fake_default_quic ×6/×11 (4), TTL 3/5/8/12 (4); фрагменты — один раз. */
    CHECK(calls == 3 + 12 && ladder_calls == 1 + 12 && r.n_trace == 15);
    {
        int controls = 0, benign = 0;
        for (int i = 0; i < calls && i < 64; i++) {
            controls += seen[i].control;
            benign += seen[i].blob_len == 16 && seen[i].copies == 1 && !seen[i].ttl;
        }
        CHECK(controls == 1 && benign == 1);
    }
    CHECK(strstr(r.reason, "fake_default_quic") != NULL);
    fake_ok_blob = -1; fake_ok_copies = 0;

    /* 3в. То же, и приманки не взяли ничего: обход по QUIC не найден, теперь
          — после перебора, а не вместо него. */
    r = run("N", "N", 0, 1);
    CHECK(r.kind == D2K_QA_NOT_FOUND && !r.incomplete && r.strategy == D2K_QS_LADDER);
    CHECK(calls == 3 + 12 && ladder_calls == 1 + 12 && data_calls == 0);
    CHECK(seen[2].control && r.frag_survives == D2K_PROP_NO);

    /* 3а. Финальное ревью core, I1: клиенту разрез CRYPTO неприменим
          (ClientHello шире датаграммы). Вопрос о разрезе не задаётся даже
          там, где коробка его пропустила бы; разрешения нет — дальше вопросы
          фрагментации, как при «нет». */
    {
        ans_clear = "N"; ans_split = "Y"; i_clear = i_split = 0;
        calls = data_calls = ladder_calls = 0;
        d2k_quic_arm_context ctx = {.pool = pool, .n_pool = 1, .next = 1, .residual = 0,
                                    .probe = probe, .marked = 1, .data = data, .no_split = 1};
        r = d2k_quic_strategy_arms(&ctx);
        CHECK(r.kind != D2K_QA_SPLIT && r.strategy != D2K_QS_SPLIT);
        CHECK(i_split == 0 && !r.split_asked && r.split_crypto == D2K_PROP_UNKNOWN);
        for (int i = 0; i < calls && i < 64; i++) CHECK(!seen[i].split);
        CHECK(r.kind == D2K_QA_NOT_FOUND && seen[1].control && strstr(r.reason, "неприменим"));
        CHECK(r.strategy == D2K_QS_LADDER && calls == 2 + 12);
    }

    /* 3б. Оба «нет», фрагменты доживают и форма 3 проходит — план из ответа. */
    frag_ok_shape = 3;
    r = run("N", "N", 0, 1);
    CHECK(r.kind == D2K_QA_FRAG && r.frag_kind == 3 && r.frag_survives == D2K_PROP_YES);
    CHECK(r.strategy == D2K_QS_FRAG && r.len == 0 && !r.incomplete);
    CHECK(calls == 2 + 1 + 3 && ladder_calls == 4 && data_calls == 1);
    frag_ok_shape = 0;

    /* 4. Фильтр прошёл, а поток оборван — это решающее «нет», не повтор. */
    r = run("C", "C", 0, 1);
    CHECK(r.kind == D2K_QA_NOT_FOUND && calls == 3 + 12 && data_calls == 2 && ladder_calls == 1 + 12);
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_NO);

    /* 5. Неустойчивый ответ — один повтор; решающий второй ответ принимается. */
    r = run("MY", "", 0, 1);
    CHECK(r.kind == D2K_QA_BLOB && r.strategy == D2K_QS_CLEARANCE && calls == 2);
    CHECK(r.n_trace == 2 && r.trace[0].answered == 1);

    /* 6. Неизмеримо и после повтора (1/3, затем этап данных не состоялся):
          стратегия из ответов не собирается — запасной перебор askArms. */
    r = run("MR", "N", 0, 1);
    CHECK(r.clearance == D2K_PROP_UNKNOWN && r.split_crypto == D2K_PROP_NO);
    /* Круг 1: вопрос, заданный до предела повторов, перебор не задаёт снова
       (0x00…0 ×1 — тот же вопрос). */
    CHECK(r.clearance_asked && r.split_asked);
    CHECK(ladder_calls == 13 && calls == 3 + 13);
    CHECK(r.strategy == D2K_QS_LADDER && r.kind == D2K_QA_NOT_FOUND);
    CHECK(r.n_trace == 3 + 13 && r.n_trace <= D2K_QUIC_ARM_STEPS);
    CHECK(r.probes == 3 * (3 + 13));
    for (int i = 3; i < calls && i < 64; i++)
        CHECK(!(seen[i].blob_len == 16 && seen[i].copies == 1 && !seen[i].ttl));

    /* 7. Не отправилось оба раза — тоже неизмеримо; запасной перебор находит. */
    ladder_pass = 1;
    r = run("EE", "EE", 0, 1);
    /* quic5 ×1, ×6, TTL 3, контроль выживания фрагментов */
    CHECK(calls == 4 + 4 && r.strategy == D2K_QS_LADDER && r.kind == D2K_QA_TTL);
    CHECK(r.clearance == D2K_PROP_UNKNOWN && r.split_crypto == D2K_PROP_UNKNOWN);
    ladder_pass = 0;

    /* 6б. Разрешения решающе нет, разрез неизмерим: запасной перебор не
           задаёт заново тот же вопрос (16 нулей ×1 перед Initial). */
    r = run("N", "EE", 0, 1);
    CHECK(r.clearance == D2K_PROP_NO && r.strategy == D2K_QS_LADDER);
    CHECK(ladder_calls == 13 && calls == 3 + 13);
    for (int i = 3; i < calls && i < 64; i++)
        CHECK(!(seen[i].blob_len == 16 && seen[i].copies == 1 && !seen[i].ttl));

    /* 8. Остаточная блокировка: каждый вопрос — свежий адрес; адреса кончились
          раньше ответа — неизмеримо, перебору тоже не на чем. */
    r = run("N", "Y", 1, 2);
    CHECK(calls == 1 && !strcmp(seen[0].addr, pool[1]));
    CHECK(r.clearance == D2K_PROP_NO && r.split_crypto == D2K_PROP_UNKNOWN);
    CHECK(r.incomplete && r.kind == D2K_QA_NOT_FOUND && ladder_calls == 0);
    CHECK(r.clearance_asked && !r.split_asked); /* адреса не было — вопрос не задан */

    /* 9. Метка не подтверждена — верить нельзя. */
    marked_ok = 0;
    r = run("Y", "", 0, 1);
    CHECK(r.kind == D2K_QA_FLAKY);
    marked_ok = 1;

    if (fails) return 1;
    puts("QUIC strategy from answers: passed");
    return 0;
}
