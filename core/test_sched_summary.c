/* Exercise production terminal/reset paths without creating a network worker. */
#define pthread_create summary_thread_create
#include "sched.c"
#undef pthread_create
#include "d2k_quic_arms.h"
#include "d2k_plantlv.h"

int summary_thread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg) {
    (void)thread; (void)attr; (void)start; (void)arg;
    return EAGAIN;
}

static int fails;
static char rows[8192];
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"summary:%d: %s\n",__LINE__,#x); fails++; } } while (0)
static void collect(void *ctx, const char *line) {
    (void)ctx;
    size_t used = strlen(rows);
    snprintf(rows + used, sizeof rows - used, "%s\n", line);
}
/* ЗАДАЧА 26: подменённая проба объёма. Мерить по «/» (или по устаревшему
   свидетелю привязки) нечем — завершённый 403 на 243 байта; обрыв даёт ТОЛЬКО
   путь, который уже наблюдался у этой цели (vol_cut_path). Проба в сеть не
   ходит: предмет проверки — какой путь спрашивает планировщик. */
static const char *vol_cut_path;
static char vol_asked[4][512];
static int vol_asks;
static d2k_vol_result vol_answer_for(const char *path) {
    d2k_vol_result r;
    memset(&r, 0, sizeof r);
    if (vol_asks < 4) snprintf(vol_asked[vol_asks], sizeof vol_asked[0], "%s", path ? path : "");
    vol_asks++;
    r.verdict = D2K_VOL_PASSED;
    r.at_kb = 40;
    if (path && vol_cut_path && !strcmp(path, vol_cut_path)) {
        r.rx_cut = 1; r.rx_compressed_complete = 1; r.rx_at_kb = 15;
        snprintf(r.measured_path, sizeof r.measured_path, "%s", path);
        snprintf(r.rx_reason, sizeof r.rx_reason, "обрыв 15985/15968, gzip завершился");
    } else {
        /* МЕРИТЬ БЫЛО НЕЧЕМ: ответ завершён и меньше полосы. Это НЕ парное
           отрицательное измерение (см. rx_short в d2k_volume.h). */
        r.rx_short = 1; r.rx_short_bytes = 243;
        snprintf(r.rx_reason, sizeof r.rx_reason, "HTTP 403, тело 243/243, complete=1");
    }
    return r;
}
static d2k_vol_result stub_vol_path(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t wire, uint32_t mark, const char *path) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12; (void)wire; (void)mark;
    return vol_answer_for(path);
}
static d2k_vol_result stub_vol_root(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t wire, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12; (void)wire; (void)mark;
    return vol_answer_for("");
}

static task *fixture(d2k_sched *s) {
    task *t = &s->tasks[0];
    memset(t, 0, sizeof *t);
    t->prop_fd = t->prop_q = t->probe_fd = t->ver.fd = t->c_fd = -1;
    strcpy(t->name, "summary.example");
    strcpy(t->ip, "127.0.0.1");
    t->port = 443; t->transport = 6; t->family = 4;
    t->shape_armed = 1;
    t->report_id = ++s->report_sequence;
    t->report_admitted_ms = 100;
    t->state = T_QUEUED;
    t->queued_ms = 800;
    t->report_queue_ms = 50; /* an earlier queue, then shape wait */
    s->now_ms = 900; s->clock_seen = 1;
    rows[0] = 0;
    return t;
}
int main(void) {
    d2k_catalog cat = {0};
    d2k_sched *s = d2k_sched_new(&cat, -1, 0x2d);
    CHECK(s != NULL);
    if (!s) return 1;
    d2k_sched_set_say(s, collect, NULL);
    for(int ladder=0;ladder<2;ladder++) {
        task *q=fixture(s);q->transport=17;q->arm.original=1;q->arm_ready=1;
        q->arm.kind=ladder?D2K_QA_COPIES:D2K_QA_UDPLEN;
        q->arm.strategy=ladder?D2K_QS_LADDER:D2K_QS_LENGTH;
        if(ladder){q->arm.bytes[0]=0x40;q->arm.len=1;q->arm.copies=1;}
        else q->arm.udplen=D2K_QUIC_LENGTH_INCREMENT;
        d2k_vres result={.verdict=D2K_V_OPAQUE};
        verdict_to_plans(s,q,&result);CHECK(q->n_plans==1);
        q->next_plan=1;
        CHECK(!strcmp(candidate_path(q),ladder?"перебор":"свойство"));
        search_report(s,q,900,"probe-confirmed",NULL);
        CHECK(strstr(rows,ladder?"path=fallback":"path=property"));
    }
    task *t = fixture(s);
    /* Real launch → pthread_create failure → reset used to lose the report. */
    CHECK(launch_task(s, t) == 0);
    CHECK(strstr(rows, "итог поиска:") != NULL);
    CHECK(strstr(rows, "elapsed_ms=800 queue_ms=150") != NULL);

    t = fixture(s);
    task_done(s, t); /* cancellation while requeued, without launch */
    CHECK(strstr(rows, "elapsed_ms=800 queue_ms=150") != NULL);

    t = fixture(s);
    t->state = T_VOICE_MEASURE; t->transport = 17;
    t->voice_res.verdict = D2K_VOICE_CLEAR;
    voice_finish_measure(s, t, s->now_ms);
    CHECK(strstr(rows, "outcome=probe-direct path=direct") != NULL);
    CHECK(strstr(rows, "outcome=failed") == NULL);

    t = fixture(s);
    t->state = T_VOICE_MEASURE; t->transport = 17;
    t->voice_res.verdict = D2K_VOICE_CLEAR;
    t->voice_known_prefix_valid = 1;
    voice_finish_measure(s, t, s->now_ms);
    CHECK(strstr(rows, "outcome=probe-clear path=unknown") != NULL);
    CHECK(strstr(rows, "path=own-plan") == NULL);

    t = fixture(s);
    t->state = T_ASKING; t->rx_volume_only = 1; t->res_ready = 1;
    t->res.verdict = D2K_V_CLEAR; t->vol.rx_cut = 0;
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=failed") == NULL);

    /* ЗАДАЧА 26, П.3: ДОКАЗАННЫЙ ПУТЬ ПЕРЕЖИВАЕТ ЭПИЗОД. Поле 12.10.2026,
       style.sndcdn.com: обрыв доказывает повтор зонда по /css/soehne-*.css, а
       следующий эпизод снова просил «/» и получал завершённый 403 на 243
       байта — измерения не было, цель уходила в покой. Сохранённый
       ДОКАЗАННЫЙ путь обязан идти первым и не вытесняться более поздней
       HTML-подсказкой того же имени: подсказка — только упоминание, а здесь
       обрыв ИЗМЕРЕН. */
    {
        const char *name = "style.cdn-vol.test";
        t = fixture(s);
        snprintf(t->ip, sizeof t->ip, "8.8.8.8");
        snprintf(t->name, sizeof t->name, "%s", name);
        t->port = 443; t->transport = 6; t->family = 4;
        t->state = T_ASKING; t->res_ready = 1; t->rx_volume_only = 1;
        t->res.verdict = D2K_V_CLEAR;
        t->vol.rx_cut = 1; t->vol.rx_at_kb = 15; t->vol.rx_compressed_complete = 1;
        snprintf(t->vol.measured_path, sizeof t->vol.measured_path, "/css/soehne-web.css");
        snprintf(t->measure_path, sizeof t->measure_path, "/css/soehne-web.css");
        s->sync_pending = 0;
        (void)d2k_sched_tick(s, 900); /* главный поток разбирает исход замера */
        /* Ни подсказок, ни подтверждённой привязки: единственное, что известно
           об этом имени, — доказанный обрыв на названном пути. Начинать заново
           с «/» значит выбросить измерение. */
        task *again = fixture(s);
        snprintf(again->ip, sizeof again->ip, "8.8.8.8");
        snprintf(again->name, sizeof again->name, "%s", name);
        again->port = 443; again->transport = 6; again->family = 4;
        select_resource_path(s, again);
        CHECK(!strcmp(again->measure_path, "/css/soehne-web.css"));
        if (strcmp(again->measure_path, "/css/soehne-web.css"))
            fprintf(stderr, "без подсказок эпизод спрашивает \"%s\" (пусто — «/») "
                            "вместо доказанного /css/soehne-web.css\n", again->measure_path);
        /* Позже HTML соседнего хоста назвал этот же хост другим ресурсом. */
        d2k_resource hint;
        memset(&hint, 0, sizeof hint);
        snprintf(hint.host, sizeof hint.host, "%s", name);
        snprintf(hint.path, sizeof hint.path, "/mentioned/only.css");
        remember_resources(s, &hint, 1);
        /* Следующий эпизод того же имени. */
        task *next = fixture(s);
        snprintf(next->ip, sizeof next->ip, "8.8.8.8");
        snprintf(next->name, sizeof next->name, "%s", name);
        next->port = 443; next->transport = 6; next->family = 4;
        select_resource_path(s, next);
        CHECK(!strcmp(next->measure_path, "/css/soehne-web.css"));
        if (strcmp(next->measure_path, "/css/soehne-web.css"))
            fprintf(stderr, "следующий эпизод спрашивает \"%s\" вместо "
                            "доказанного /css/soehne-web.css\n", next->measure_path);
    }

    /* ЗАДАЧА 26, П.4: ПОДСКАЗКА ИЗ ПАМЯТИ ПЛАНИРОВЩИКА. Хост, отдающий 403/401
       на любой путь, подсказку о своих ресурсах не даёт НИКОГДА: verify.c
       собирает их только из завершённого 2xx text/html. Значит путь берётся из
       уже наблюдавшихся по этой цели — здесь свидетель привязки (/witness.css)
       успел устареть и тоже ничего не измерил, а в памяти лежит ресурс
       /observed.css, увиденный в чужом HTML. Один повтор по названной причине
       «мерить было нечем», только наблюдавшийся путь, и тот же
       d2k_resource_path_ok. */
    {
        const char *name = "assets.cdn-vol.test";
        cat.boxes = calloc(1, sizeof *cat.boxes);
        CHECK(cat.boxes != NULL);
        if (cat.boxes) {
            cat.n_boxes = 1;
            snprintf(cat.boxes[0].id, sizeof cat.boxes[0].id, "box-vol-26");
            cat.boxes[0].binds = calloc(1, sizeof *cat.boxes[0].binds);
            CHECK(cat.boxes[0].binds != NULL);
            cat.boxes[0].n_binds = cat.boxes[0].binds ? 1 : 0;
        }
        if (cat.n_boxes && cat.boxes[0].n_binds) {
            d2k_cat_binding *bd = &cat.boxes[0].binds[0];
            snprintf(bd->kind, sizeof bd->kind, "name");
            snprintf(bd->target, sizeof bd->target, "%s", name);
            snprintf(bd->plan_id, sizeof bd->plan_id, "00000000000000000000000000000026");
            snprintf(bd->probe_path, sizeof bd->probe_path, "/witness.css");
            bd->level = 3; bd->enabled = 1; bd->confirmed = 100;
            bd->transport = 6; bd->family = 4; bd->shape = (uint8_t)D2K_SHAPE_MODERN;
        }
        d2k_resource seen;
        memset(&seen, 0, sizeof seen);
        snprintf(seen.host, sizeof seen.host, "%s", name);
        snprintf(seen.path, sizeof seen.path, "/observed.css");
        remember_resources(s, &seen, 1);
        t = fixture(s);
        snprintf(t->ip, sizeof t->ip, "8.8.8.8");
        snprintf(t->name, sizeof t->name, "%s", name);
        t->port = 443; t->transport = 6; t->family = 4;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, name, t->trig,
                                     sizeof t->trig, &t->trig_len) == 0);
        select_resource_path(s, t);
        CHECK(!strcmp(t->measure_path, "/witness.css"));
        d2k_sched_vol_path_hook = stub_vol_path;
        d2k_sched_vol_hook = stub_vol_root;
        vol_cut_path = "/observed.css";
        vol_asks = 0;
        d2k_hello trig;
        trig.bytes = t->trig; trig.len = t->trig_len;
        worker_volume(s, t, trig);
        CHECK(vol_asks == 2 && !strcmp(vol_asked[0], "/witness.css") &&
              !strcmp(vol_asked[1], "/observed.css"));
        CHECK(t->vol.rx_cut && !strcmp(t->measure_path, "/observed.css"));
        if (vol_asks != 2 || !t->vol.rx_cut)
            fprintf(stderr, "замеров %d (первый \"%s\", второй \"%s\"), rx_cut=%d, "
                            "путь кандидата \"%s\"\n",
                    vol_asks, vol_asked[0], vol_asks > 1 ? vol_asked[1] : "-",
                    t->vol.rx_cut, t->measure_path);
        d2k_sched_vol_path_hook = d2k_volume_probe_path;
        d2k_sched_vol_hook = d2k_volume_probe;
        vol_cut_path = NULL;
    }
    /* ЗАЩИТА ОТ ВБРОШЕННОГО СБРОСА ПРОСИТСЯ ПО ИЗМЕРЕННОМУ ПОВОДУ.
     * Поле 13.10.2026, forum.ru-board.com: рукопожатие снято, план применён
     * ко всем 133 потокам, сервер ответил всем, и коробка вбросила сброс в
     * 132 — TTL 127 против 55–57 у сервера, каждый В ОКНО. Строку
     * `guard rst_alien` не выдавал ни один сборщик, и реализованная в
     * датапате защита не включалась никогда. */
    {
        char text[512];
        task probe;
        memset(&probe, 0, sizeof probe);
        probe.transport = 6;
        probe.trigger_code = D2K_SUSPECT_RST;
        CHECK(rst_guard_wanted(&probe));
        probe.trigger_code = D2K_SUSPECT_RST_AFTER_APP;
        CHECK(rst_guard_wanted(&probe));
        probe.trigger_code = D2K_SUSPECT_RST_CUT;
        CHECK(rst_guard_wanted(&probe));
        /* Тишина и объём поводом не являются. */
        probe.trigger_code = D2K_SUSPECT_SILENT;
        CHECK(!rst_guard_wanted(&probe));
        /* QUIC — другой транспорт: там нет TCP-сброса. */
        probe.trigger_code = D2K_SUSPECT_RST; probe.transport = 17;
        CHECK(!rst_guard_wanted(&probe));

        snprintf(text, sizeof text, "d2k-plan 1 5\nproto tcp tls\n");
        CHECK(plan_arm_rst_guard(text, sizeof text) == 1);
        CHECK(strstr(text, "guard rst_alien\n") != NULL);
        /* Второй раз не дописывается. */
        CHECK(plan_arm_rst_guard(text, sizeof text) == 0);
        /* Текст остаётся годным планом: защита уезжает в провод записью. */
        uint8_t tlv[D2K_PLAN_TLV_MAX]; size_t tlv_len = 0; char err[200];
        CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, err, sizeof err) == 0);
        int found = 0;
        for (size_t at = 12; at + 4 <= tlv_len;) {
            unsigned rec = ((unsigned)tlv[at] << 8) | tlv[at + 1];
            size_t sz = ((size_t)tlv[at + 2] << 8) | tlv[at + 3];
            at += 4;
            if (sz > tlv_len - at) { break; }
            if (rec == 0x0104 && sz == 1 && tlv[at] == 1) { found = 1; }
            at += sz;
        }
        CHECK(found);
        /* ПОВОД ДЛЯ КЛИЕНТСКИХ ПРИВЯЗОК — ИЗМЕРЕННАЯ ПРИМЕТА КОРОБКИ.
         * Зонд судит по своему триггеру, а привязка в каталоге живёт дольше
         * задачи: её повод — примета «rst» в отпечатке коробки, записанная
         * тем же замером. */
        d2k_cat_box box;
        memset(&box, 0, sizeof box);
        CHECK(!box_injects_rst(&box));
        box.fp.n_sig = 2;
        snprintf(box.fp.sig[0].kind, sizeof box.fp.sig[0].kind, "%s", "volume");
        snprintf(box.fp.sig[1].kind, sizeof box.fp.sig[1].kind, "%s", "silent");
        CHECK(!box_injects_rst(&box));
        snprintf(box.fp.sig[1].kind, sizeof box.fp.sig[1].kind, "%s", "rst");
        CHECK(box_injects_rst(&box));
        CHECK(!box_injects_rst(NULL));

        /* Не поместилась — план идёт как был, а не теряется. */
        char tight[40];
        snprintf(tight, sizeof tight, "d2k-plan 1 5\nproto tcp tls\n");
        CHECK(plan_arm_rst_guard(tight, strlen(tight) + 4) == 0);
    }

    d2k_sched_free(s);
    d2k_catalog_free(&cat);
    if (fails) fprintf(stderr, "summary: %d failures\n", fails);
    return fails ? 1 : 0;
}
