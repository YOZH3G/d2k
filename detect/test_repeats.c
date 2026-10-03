/* test_repeats.c — повторы, которые не меняют исход, не тратятся.
 *
 * Стенд: классификатор и свойства собраны в ЭТОМ же модуле (#include .c),
 * а сырой слой подменён сценарием ответов — как test_raw.c подменяет сокеты.
 * Сокетные зонды (база, разрез, контроль) идут на настоящую петлю: коробка
 * «решает по содержимому» — пропускает только контрольную нагрузку.
 *
 * Эквивалентность «до/после»: подписи вердиктов ниже СНЯТЫ с кода ДО правки
 * (те же сценарии, те же ответы, все повторы). Совпадение подписи значит, что
 * вердикт, путь, находка, стратегия и вектор свойств не изменились; меняется
 * только число зондов. */
#define d2k_raw_probe_handshake_family fake_handshake
#define d2k_raw_probe_poison_family    fake_poison
#define d2k_raw_supported              fake_raw_supported
#define d2k_raw_rst_fail_count         fake_rst_fail_count
#include "classify.c"
#include "props.c"

#include <pthread.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("  ПРОВАЛ %d: ", __LINE__); \
    printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* --- сценарий сырого слоя ------------------------------------------------ */
/* Шаблон: по символу на ПОВТОР одного вопроса, последний символ тянется.
 * '+' прошло, '-' нет, 'e' локальная ошибка зонда (rc<0). Счёт повторов
 * начинается заново у каждого вопроса (каждой строки трассы): один и тот же
 * вопрос, заданный дважды (свойство и затем перебор), получает одинаковые
 * ответы, а не продолжение чужого счётчика — иначе ранняя остановка сдвинула
 * бы ответы следующего вопроса и «одинаковые ответы» перестали бы быть
 * одинаковыми. */
typedef struct { const char *name; const char *pat; } script_ent;

static const script_ent *g_script;
static const char *g_default = "-";
static const char *g_selftest = "+";
static const d2k_result *g_res;   /* чей прогон идёт: номер строки трассы = вопрос */
static int g_ask = -1, g_rep;     /* текущий вопрос сырого слоя и номер его повтора */
static int g_hs_calls;
static int g_poison_calls;

static int pat_rc(const char *pat, int idx)
{
    size_t n = strlen(pat);
    char c = pat[(size_t)idx < n ? (size_t)idx : n - 1];
    return c == '+' ? 1 : c == 'e' ? -1 : 0;
}

static int next_rep(void)
{
    if (g_res->ntrace != g_ask) {
        g_ask = g_res->ntrace;
        g_rep = 0;
    }
    return g_rep++;
}

int fake_raw_supported(void) { return 1; }
unsigned long fake_rst_fail_count(void) { return 0; }

int fake_handshake(const uint8_t *ip, uint8_t family, uint16_t port, int timeout_ms,
                   uint32_t mark, const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    int rc;
    (void)ip; (void)family; (void)port; (void)timeout_ms; (void)mark; (void)cancel;
    g_hs_calls++;
    rc = pat_rc(g_selftest, next_rep());
    if (rc < 0) { snprintf(err, errcap, "classify: SYN-ACK не пришёл"); }
    return rc;
}

int fake_poison(const uint8_t *ip, uint8_t family, uint16_t port, const d2k_trigger *tr,
                const d2k_poison *p, int timeout_ms, uint32_t mark,
                const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    const char *pat = g_default;
    int i, rc;
    (void)ip; (void)family; (void)port; (void)tr; (void)timeout_ms; (void)mark; (void)cancel;
    g_poison_calls++;
    for (i = 0; g_script && g_script[i].name; i++) {
        if (strcmp(g_script[i].name, p->name) == 0) { pat = g_script[i].pat; break; }
    }
    rc = pat_rc(pat, next_rep());
    if (rc < 0) { snprintf(err, errcap, "sendto: Operation not permitted"); }
    return rc;
}

/* --- коробка на петле ---------------------------------------------------- */
static const char CTL[] = "BENIGN-CONTROL-PAYLOAD";
static const char *g_ctl_pat = "+"; /* ответ на контрольную нагрузку по вызовам */
static int g_ctl_calls;
static int g_srv_fd;

static void *srv_thread(void *arg)
{
    (void)arg;
    for (;;) {
        uint8_t buf[256];
        ssize_t n;
        int c = accept(g_srv_fd, NULL, NULL);
        if (c < 0) { return NULL; }
        n = recv(c, buf, sizeof buf, 0);
        if (n == (ssize_t)(sizeof(CTL) - 1) && memcmp(buf, CTL, (size_t)n) == 0 &&
            pat_rc(g_ctl_pat, g_ctl_calls++) > 0) {
            (void)send(c, "OK", 2, 0);
        }
        close(c); /* обрыв = «убито», мгновенно */
    }
}

static char g_addr[64];

static void srv_start(void)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    pthread_t th;
    int one = 1;
    g_srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    (void)setsockopt(g_srv_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001u);
    if (bind(g_srv_fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_srv_fd, 64) != 0 ||
        getsockname(g_srv_fd, (struct sockaddr *)&sa, &sl) != 0) {
        printf("стенд не поднялся\n");
        exit(1);
    }
    snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)ntohs(sa.sin_port));
    pthread_create(&th, NULL, srv_thread, NULL);
    pthread_detach(th);
}

/* --- прогон -------------------------------------------------------------- */
static const char PAY[] = "WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES";

typedef struct {
    const char       *name;
    const script_ent *script;
    const char       *dflt;
    const char       *selftest;
    const char       *ctl;
    int               vouched;
} scenario;

static void run(const scenario *s, d2k_result *res)
{
    d2k_opts opt;
    d2k_trigger t;
    memset(&opt, 0, sizeof opt);
    opt.allow_loopback = 1;
    opt.repeats = 3;
    opt.timeout_ms = 400;
    opt.write_gap_ms = 2;
    opt.long_gap_ms = 10;
    opt.control_vouched = s->vouched;
    memset(&opt.control, 0, sizeof opt.control);
    snprintf(opt.control.name, sizeof opt.control.name, "control");
    memcpy(opt.control.payload, CTL, sizeof(CTL) - 1);
    opt.control.len = sizeof(CTL) - 1;
    opt.control.accept = D2K_ACCEPT_ANY;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "test");
    memcpy(t.payload, PAY, sizeof(PAY) - 1);
    t.len = sizeof(PAY) - 1;
    t.accept = D2K_ACCEPT_ANY;

    g_script = s->script;
    g_default = s->dflt ? s->dflt : "-";
    g_selftest = s->selftest ? s->selftest : "+";
    g_ctl_pat = s->ctl ? s->ctl : "+";
    g_ctl_calls = 0;
    g_res = res;
    g_ask = -1;
    g_hs_calls = 0;
    g_poison_calls = 0;
    d2k_classify_run(g_addr, &t, &opt, res);
}

/* Подпись исхода: всё, что уходит наружу, кроме числа зондов и трассы. */
static void sig(const d2k_result *r, char *out, size_t cap)
{
    const d2k_dprops *p = &r->props;
    snprintf(out, cap, "%s|%s|%s|%s|%d%d%d%d%d%d%d|%d|u%d|f%d|%s",
             d2k_verdict_name(r->verdict), r->path, r->has_hit ? r->hit.name : "-",
             r->strategy, p->reassembles, p->parses_l7, p->validates_checksum,
             p->tolerates_reorder, p->tolerates_left_overlap, p->counts_duplicates,
             p->inspects_syn, p->hop_ttl, r->raw_usable, r->raw_selftest_failed, r->reason);
}

static void dump(const d2k_result *r)
{
    int i;
    for (i = 0; i < r->ntrace; i++) {
        printf("    %-40s прошло=%d не прошло=%d %s\n", r->trace[i].probe, r->trace[i].pass,
               r->trace[i].fail, r->trace[i].err);
    }
}

/* Сценарии. Имена гипотез перебора берутся из списка по номеру ниже. */
static const script_ent S_YOUTUBE[] = {
    {"seqovl-1", "-"}, {"disorder", "+"}, {NULL, NULL}};
static script_ent S_RUTRACKER[] = {{NULL, "+"}, {NULL, NULL}};
static script_ent S_FLAKY[] = {
    {"seqovl-1", "+-"}, {"disorder", "-+"}, {"badsum", "++-"},
    {NULL, "++-"}, {NULL, "+"}, {NULL, NULL}};
static const script_ent S_PROPHIT_L7[] = {{"badsum+hello", "+"}, {NULL, NULL}};

static scenario SC[] = {
    {"youtube", S_YOUTUBE, NULL, NULL, NULL, 0},
    {"rutracker", S_RUTRACKER, NULL, NULL, NULL, 0},
    {"flaky", S_FLAKY, NULL, NULL, NULL, 0},
    {"prop-l7", S_PROPHIT_L7, NULL, NULL, NULL, 0},
    {"none-pass", NULL, "-", NULL, NULL, 0},
    {"selftest-fail", NULL, "-", "e", NULL, 0},
    {"selftest-late", S_YOUTUBE, NULL, "-e+", NULL, 0},
    {"ctl-late", S_YOUTUBE, NULL, NULL, "-+", 0},
    {"ctl-dead", NULL, "-", NULL, "-", 0},
    {"ctl-dead-vouched", NULL, "-", NULL, "-", 1},
    {"ctl-dead-hit", S_YOUTUBE, NULL, NULL, "-", 1},
    {"errors", NULL, "e", NULL, NULL, 0},
};
#define NSC ((int)(sizeof SC / sizeof SC[0]))

static void bind_list_names(void)
{
    int n;
    const d2k_poison *l = d2k_poisons(&n);
    /* rutracker: сорок первая гипотеза перебора срабатывает. */
    S_RUTRACKER[0].name = l[40].name;
    /* flaky: 2 из 3 на одной, единогласие на следующей. */
    S_FLAKY[3].name = l[10].name;
    S_FLAKY[4].name = l[11].name;
}

/* Подписи СНЯТЫ с кода до правки (все повторы на каждом вопросе), прогон
 * с чистым процессом. before — сколько зондов стоил тот прогон; сколько
 * обязан стоить теперь — в after_count. */
typedef struct { const char *name; int before; const char *sig; } golden;
static const golden GOLD[] = {
{"youtube", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"rutracker", 156, "poisonable|перебор|seqovl-16|--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=16|0002100|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «seqovl-16», сервер выбрасывает"},
{"flaky", 69, "poisonable|перебор|fakedsplit|--lua-desync=fakedsplit:payload=tls_client_hello:dir=out:pos=1:badsum|0012200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «fakedsplit», сервер выбрасывает"},
{"prop-l7", 24, "poisonable|свойство|badsum+hello|--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com:badsum|0212200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «badsum+hello», сервер выбрасывает"},
{"none-pass", 297, "opaque||-||0002200|0|u1|f0|разрез не помогает, контроль проходит, отравить буфер не удалось — содержимое важно, но чем брать, зондами не нашли"},
{"selftest-fail", 12, "opaque||-||0000000|0|u0|f1|разрез не помогает, контроль проходит; сырые зонды НЕ РАБОТАЮТ (самопроверка не прошла) — про отравление вывода нет"},
{"selftest-late", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"ctl-late", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"ctl-dead", 297, "inconclusive||-||0002200|0|u1|f0|контроль не ответил и отравить не удалось: базы нет, отличить блок по адресу от нехватки гипотез нельзя"},
{"ctl-dead-vouched", 297, "address||-||0002200|0|u1|f0|молчит и контроль на имени, за которое ручается оператор, и ни одна гипотеза не сработала — похоже на блок по адресу"},
{"ctl-dead-hit", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"errors", 297, "opaque||-||0002200|0|u1|f0|разрез не помогает, контроль проходит, отравить буфер не удалось — содержимое важно, но чем брать, зондами не нашли"},
};

static int after_count(const char *name)
{
    /* Полный перебор — на 3 зонда дешевле (задача 49): три точных дубля
       донора (badsum-x2-g20, badsum-x2-g80, badsum-x7-g0) больше не
       спрашиваются второй раз. */
    static const struct { const char *n; int a; } A[] = {
        {"youtube", 12}, {"rutracker", 58}, {"flaky", 37}, {"prop-l7", 14},
        {"none-pass", 100}, {"selftest-fail", 10}, {"selftest-late", 14},
        {"ctl-late", 13}, {"ctl-dead", 102}, {"ctl-dead-vouched", 102},
        {"ctl-dead-hit", 14}, {"errors", 100}};
    size_t i;
    for (i = 0; i < sizeof A / sizeof A[0]; i++) {
        if (strcmp(A[i].n, name) == 0) { return A[i].a; }
    }
    return -1;
}

static const scenario *find_sc(const char *name)
{
    int i;
    for (i = 0; i < NSC; i++) {
        if (strcmp(SC[i].name, name) == 0) { return &SC[i]; }
    }
    return NULL;
}

static const golden *find_gold(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof GOLD / sizeof GOLD[0]; i++) {
        if (strcmp(GOLD[i].name, name) == 0) { return &GOLD[i]; }
    }
    return NULL;
}

/* Чистый процесс: кэша самопроверки нет, счёт ошибок пуст. */
static void fresh_process(void)
{
    pthread_mutex_lock(&g_selftest_mu);
    memset(g_selftest_ok, 0, sizeof g_selftest_ok);
    memset(g_selftest_at, 0, sizeof g_selftest_at);
    memset(g_raw_err_streak, 0, sizeof g_raw_err_streak);
    pthread_mutex_unlock(&g_selftest_mu);
}

static const d2k_obs *find_obs(const d2k_result *r, const char *probe)
{
    int i;
    for (i = 0; i < r->ntrace; i++) {
        if (strcmp(r->trace[i].probe, probe) == 0) { return &r->trace[i]; }
    }
    return NULL;
}

/* Трасса честна: сумма pass+fail по строкам = число сделанных зондов. */
static int trace_probes(const d2k_result *r)
{
    int i, n = 0;
    for (i = 0; i < r->ntrace; i++) { n += r->trace[i].pass + r->trace[i].fail; }
    return n;
}

static void test_equivalence(void)
{
    int i;
    printf("до/после: одинаковые ответы — одинаковый исход\n");
    for (i = 0; i < NSC; i++) {
        const golden *g = find_gold(SC[i].name);
        d2k_result r;
        char s[1400];
        fresh_process();
        run(&SC[i], &r);
        sig(&r, s, sizeof s);
        CHECK(g && strcmp(s, g->sig) == 0, "%s: исход разошёлся\n    было  %s\n    стало %s",
              SC[i].name, g ? g->sig : "?", s);
        CHECK(r.probes == after_count(SC[i].name), "%s: зондов %d, ждали %d (было %d)",
              SC[i].name, r.probes, after_count(SC[i].name), g ? g->before : -1);
        CHECK(trace_probes(&r) == r.probes, "%s: трасса показывает %d зондов, сделано %d",
              SC[i].name, trace_probes(&r), r.probes);
        printf("  %-18s зондов %3d -> %3d\n", SC[i].name, g ? g->before : -1, r.probes);
        if (getenv("DUMP")) { dump(&r); }
    }
}

static void test_counts_per_question(void)
{
    d2k_result r;
    const d2k_obs *o;
    printf("повторы по вопросам\n");
    fresh_process();
    run(find_sc("youtube"), &r);
    o = find_obs(&r, "control");
    CHECK(o && o->pass == 1 && o->fail == 0, "(a) контроль: ждали 1 зонд до первого прохода");
    o = find_obs(&r, "raw-selftest");
    CHECK(o && o->pass == 1 && o->fail == 0, "самопроверка: ждали 1 зонд до первого успеха");
    o = find_obs(&r, "свойство:перекрытие слева");
    CHECK(o && o->pass == 0 && o->fail == 1, "(b) провал на первом повторе: ждали 1 зонд");
    o = find_obs(&r, "свойство:порядок сегментов");
    CHECK(o && o->pass == 3 && o->fail == 0, "(c) проход: ждали все 3 повтора");
    o = find_obs(&r, "whole");
    CHECK(o && o->pass + o->fail == 3, "база: все повторы");
    o = find_obs(&r, "split");
    CHECK(o && o->pass + o->fail == 3, "разрез: все повторы");
    fresh_process();
    run(find_sc("ctl-dead"), &r);
    o = find_obs(&r, "control");
    CHECK(o && o->pass == 0 && o->fail == 3, "контроль без прохода: все 3 повтора");
}

static void test_selftest_cache(void)
{
    d2k_result r;
    char s[1400];
    const golden *g;
    printf("самопроверка сырого слоя: раз на процесс\n");

    /* (d) второй прогон в том же процессе самопроверку не повторяет. */
    fresh_process();
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 1, "первый прогон: самопроверок %d, ждали 1", g_hs_calls);
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 0, "второй прогон: самопроверок %d, ждали 0", g_hs_calls);
    CHECK(r.probes == 11, "второй прогон: зондов %d, ждали 11", r.probes);
    CHECK(find_obs(&r, "raw-selftest:кэш") != NULL, "трасса не говорит, что самопроверка из кэша");
    CHECK(find_obs(&r, "raw-selftest") == NULL, "в трассе зонд самопроверки, которого не было");
    CHECK(trace_probes(&r) == r.probes, "трасса показывает %d зондов, сделано %d",
          trace_probes(&r), r.probes);
    sig(&r, s, sizeof s);
    g = find_gold("youtube");
    CHECK(strcmp(s, g->sig) == 0, "исход из кэша разошёлся: %s", s);

    /* Подряд идущие локальные ошибки сырых зондов — самопроверка снова. */
    {
        d2k_result junk;
        memset(&junk, 0, sizeof junk);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
    }
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 1, "после серии отказов: самопроверок %d, ждали 1", g_hs_calls);

    /* Удача сбрасывает счёт: две ошибки, удача, две ошибки — кэш жив. */
    {
        d2k_result junk;
        memset(&junk, 0, sizeof junk);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, 0);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
    }
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 0, "ошибки вперемешку с удачей: самопроверок %d, ждали 0", g_hs_calls);

    /* Кэш стареет. */
    pthread_mutex_lock(&g_selftest_mu);
    g_selftest_at[0] -= D2K_SELFTEST_TTL_MS + 1;
    pthread_mutex_unlock(&g_selftest_mu);
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 1, "кэш старше срока: самопроверок %d, ждали 1", g_hs_calls);

    /* Кэш есть, а сырой слой сломался: первые же отказы этого прогона
     * перепроверяют слой, и провал ведёт себя ровно как провал самопроверки. */
    {
        scenario broken = {"broken", NULL, "e", "e", NULL, 0};
        fresh_process();
        run(find_sc("youtube"), &r);
        run(&broken, &r);
        CHECK(g_hs_calls >= 1, "сломанный слой при кэше не перепроверен");
        sig(&r, s, sizeof s);
        g = find_gold("selftest-fail");
        CHECK(strcmp(s, g->sig) == 0, "сломанный слой при кэше:\n    ждали %s\n    стало %s",
              g->sig, s);
        CHECK(trace_probes(&r) == r.probes, "трасса показывает %d зондов, сделано %d",
              trace_probes(&r), r.probes);
        /* и следующий прогон снова мерит слой, а не верит кэшу */
        run(find_sc("youtube"), &r);
        CHECK(g_hs_calls == 1, "после провала перепроверки: самопроверок %d, ждали 1",
              g_hs_calls);
    }

    /* Кэш есть, сырые зонды отказывают, но слой исправен (цель не отвечает
     * сырому SYN): перепроверка проходит, исход тот же, что без кэша. */
    {
        fresh_process();
        run(find_sc("youtube"), &r);
        run(find_sc("errors"), &r);
        sig(&r, s, sizeof s);
        g = find_gold("errors");
        CHECK(strcmp(s, g->sig) == 0, "отказы при исправном слое:\n    ждали %s\n    стало %s",
              g->sig, s);
        CHECK(trace_probes(&r) == r.probes, "трасса показывает %d зондов, сделано %d",
              trace_probes(&r), r.probes);
    }
}

int main(void)
{
    srv_start();
    bind_list_names();
    if (getenv("CAPTURE")) {
        int i;
        for (i = 0; i < NSC; i++) {
            d2k_result r;
            char s[1400];
            run(&SC[i], &r);
            sig(&r, s, sizeof s);
            printf("{\"%s\", %d, \"%s\"},\n", SC[i].name, r.probes, s);
        }
        return 0;
    }
    test_equivalence();
    test_counts_per_question();
    test_selftest_cache();
    if (fails) {
        printf("повторы: ПРОВАЛОВ %d\n", fails);
        return 1;
    }
    printf("повторы: лишних нет, исходы совпадают\n");
    return 0;
}
