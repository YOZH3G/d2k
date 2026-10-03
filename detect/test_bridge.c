/* Contract tests for the production scheduler adapter, without network.
 * The classifier itself is exercised by test_tree; here its input/output
 * is intercepted so a correct classifier cannot hide a broken adapter. */
#include "d2k_detect.h"
#include "d2k_verdict.h"
#include <stdio.h>
#include <string.h>

d2k_vres d2k_detect_sched_tcp(const char *, uint16_t, d2k_hello, d2k_hello,
                             uint32_t, int, uint32_t, uint32_t);
d2k_vres d2k_detect_sched_tcp_base(const char *, uint16_t, d2k_hello, d2k_hello,
                                  uint32_t, int, uint32_t, uint32_t,
                                  const volatile sig_atomic_t *);
d2k_vres d2k_detect_sched_tcp_seeded(const char *, uint16_t, d2k_hello, d2k_hello,
                                    uint32_t, int, uint32_t, uint32_t,
                                    const volatile sig_atomic_t *, const d2k_base_seed *);
int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);

static d2k_opts seen;
static d2k_result answer;
static int failures;
static char seen_name[D2K_TRIGGER_NAME_MAX];
static int rule_failed;
static int base_stop_before, base_stop_other, base_stop_after;

/* raw.o is not linked here: the adapter only asks whether the kernel-RST
 * suppression rule ever failed in this process. */
unsigned long d2k_raw_rst_fail_count(void) { return (unsigned long)rule_failed; }
/* Сырые соединения потока: по умолчанию прогон ходил сырым слоем. */
static int dialled = 1;
unsigned long d2k_raw_dial_count(void) { return (unsigned long)dialled; }

/* Ход измерителя (задача 48): sched.o здесь не линкуется, приёмник
 * планировщика подменён записью вызовов. */
static int progress_calls, progress_probes;
static char progress_last[160];
void d2k_sched_progress_note(const char *question, int pass, int fail)
{
    progress_calls++;
    progress_probes += pass + fail;
    snprintf(progress_last, sizeof progress_last, "%s", question);
}
static void progress_reset(void)
{
    progress_calls = progress_probes = 0;
    progress_last[0] = '\0';
}
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "bridge:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

void d2k_classify_run(const char *addr, const d2k_trigger *tr,
                      d2k_opts *opt, d2k_result *res)
{
    CHECK(strcmp(addr, "192.0.2.1:443") == 0);
    CHECK(tr->len >= 2 && tr->payload[0] == 0x16);
    snprintf(seen_name, sizeof seen_name, "%s", tr->name);
    seen = *opt;
    *res = answer;
    /* Базовый вопрос (задача 32): остановка взводится ровно наблюдением
       "whole" — до него дерево не бросается, после — бросается. */
    if (opt->on_obs) {
        d2k_obs other, whole;
        memset(&other, 0, sizeof other); memset(&whole, 0, sizeof whole);
        snprintf(other.probe, sizeof other.probe, "split");
        snprintf(whole.probe, sizeof whole.probe, "whole");
        other.fail = 3;
        whole.pass = 1; whole.fail = 2;
        base_stop_before = opt->cancel.fn(opt->cancel.ctx);
        opt->on_obs(opt->on_obs_ctx, &other);
        base_stop_other = opt->cancel.fn(opt->cancel.ctx);
        opt->on_obs(opt->on_obs_ctx, &whole);
        base_stop_after = opt->cancel.fn(opt->cancel.ctx);
    }
}

static size_t build_hello(uint8_t *o, const char *sni);

static d2k_vres measure_base(int pass, int fail, const char *err)
{
    uint8_t hello[300], ctl[] = {0x16, 0x03, 0x01};
    d2k_hello tr = {hello, build_hello(hello, "base.example")}, control = {ctl, sizeof ctl};
    memset(&answer, 0, sizeof answer);
    answer.verdict = D2K_DV_PREFIX; /* дальше дерево не идёт — вердикт не берётся */
    answer.repeats = 2;
    answer.ntrace = 2;
    snprintf(answer.trace[0].probe, sizeof answer.trace[0].probe, "whole");
    answer.trace[0].pass = pass;
    answer.trace[0].fail = fail;
    snprintf(answer.trace[0].err, sizeof answer.trace[0].err, "%s", err);
    snprintf(answer.trace[1].probe, sizeof answer.trace[1].probe, "split");
    base_stop_before = base_stop_other = base_stop_after = -1;
    return d2k_detect_sched_tcp_base("192.0.2.1", 443, tr, control, 0x2d, 2, 12000, 321, NULL);
}

static d2k_vres measure(void)
{
    uint8_t hello[] = {0x16, 0x03};
    uint8_t ctl[] = {0x16, 0x03, 0x01};
    d2k_hello tr = {hello, sizeof hello}, control = {ctl, sizeof ctl};
    return d2k_detect_sched_tcp("192.0.2.1", 443, tr, control,
                                0x2d, 2, 12000, 321);
}

static size_t build_hello(uint8_t *o, const char *sni)
{
    size_t n = strlen(sni), p = 0, ext = 9 + n, body = 2 + 32 + 1 + 4 + 2 + 2 + ext;
    const uint8_t a[] = {0x16, 0x03, 0x01};
    memcpy(o, a, 3); p = 3;
    o[p++] = (body + 4) >> 8; o[p++] = (body + 4) & 255;
    o[p++] = 1; o[p++] = 0; o[p++] = body >> 8; o[p++] = body & 255;
    o[p++] = 3; o[p++] = 3;
    memset(o + p, 7, 32); p += 32;
    o[p++] = 0;
    o[p++] = 0; o[p++] = 2; o[p++] = 0; o[p++] = 0x2f;
    o[p++] = 1; o[p++] = 0;
    o[p++] = ext >> 8; o[p++] = ext & 255;
    o[p++] = 0; o[p++] = 0; o[p++] = (n + 5) >> 8; o[p++] = (n + 5) & 255;
    o[p++] = (n + 3) >> 8; o[p++] = (n + 3) & 255;
    o[p++] = 0; o[p++] = n >> 8; o[p++] = n & 255;
    memcpy(o + p, sni, n); p += n;
    return p;
}

int main(void)
{
    d2k_vres r;
    d2k_arm arm;
    d2k_poison p;
    char why[160];
    {
        d2k_hello empty = {0};
        r = d2k_detect_sched_tcp("192.0.2.1", 443, empty, empty, 0x2d, 2, 12000, 321);
        CHECK(r.owns_search && !r.have_arm && r.verdict == D2K_V_FLAKY);
    }
    {
        /* The response-direction probe takes its SNI from tr.name; it must be
         * the client's name, never the address being measured. */
        uint8_t h[300], c[] = {0x16, 0x03, 0x01};
        d2k_hello tr, ctl = {c, sizeof c};
        tr.bytes = h;
        tr.len = build_hello(h, "blocked.example");
        answer.verdict = D2K_DV_INCONCLUSIVE; answer.has_hit = 0;
        d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321);
        CHECK(strcmp(seen_name, "tls:blocked.example") == 0);
        /* Real hello, no server_name extension. */
        {
            uint8_t g[300];
            size_t n = build_hello(g, "x.example");
            /* turn server_name (type 0) into an unknown extension type */
            g[n - strlen("x.example") - 9 + 0] = 0xff;
            g[n - strlen("x.example") - 9 + 1] = 0xff;
            tr.bytes = g; tr.len = n;
            seen_name[0] = 'Z';
            d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321);
            CHECK(seen_name[0] == '\0');
        }
        /* Max-length SNI is held whole. */
        {
            char big[254], want[300];
            uint8_t g[600];
            memset(big, 'a', 253); big[253] = 0;
            tr.bytes = g; tr.len = build_hello(g, big);
            seen_name[0] = 'Z';
            d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321);
            snprintf(want, sizeof want, "tls:%s", big);
            CHECK(strcmp(seen_name, want) == 0);
        }
        /* Embedded NUL: no name. */
        {
            uint8_t g[300];
            size_t n = build_hello(g, "ab.example");
            g[n - 5] = 0;
            tr.bytes = g; tr.len = n;
            seen_name[0] = 'Z';
            d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321);
            CHECK(seen_name[0] == '\0');
        }
    }
    answer.verdict = D2K_DV_INCONCLUSIVE;
    r = measure();
    CHECK(seen.control.len == 3);
    CHECK(seen.control_vouched == 0); /* automatic control != operator promise */
    CHECK(seen.mark == 0x2d && seen.repeats == 2);
    CHECK(seen.write_gap_ms == 12 && seen.timeout_ms == 321);
    CHECK(r.verdict == D2K_V_INCONCLUSIVE);
    CHECK(r.owns_search && r.split_gap_us == 12000);

    answer.verdict = D2K_DV_POISONABLE;
    answer.has_hit = 1;
    strcpy(answer.hit.name, "seqovl-1");
    answer.hit.seqovl = 1;
    r = measure();
    CHECK(r.have_arm && r.arm.seqovl == 1);
    CHECK(strcmp(r.arm_name, "seqovl-1") == 0);
    /* d2k_vres is returned and repeatedly copied by value. No pointer into
     * the adapter's dead stack frame may escape with the result. */
    CHECK(r.arm.name == NULL);
    CHECK(r.arm_input.trigger_len == 2);
    {
        uint8_t decoy[] = {0xa1, 0, 0x7f};
        answer.hit.decoy = decoy;
        answer.hit.decoy_len = sizeof decoy;
        r = measure();
        decoy[0] = 0xff;
        CHECK(r.arm_input.decoy_len == 3 && r.arm_input.decoy[0] == 0xa1);
        CHECK(r.arm_input.decoy[1] == 0); /* binary, not a C string */
        d2k_vres copied = r;
        memset(&r, 0, sizeof r);
        CHECK(copied.arm_input.decoy[0] == 0xa1);
        answer.hit.decoy_len = D2K_ARM_DECOY_MAX + 1;
        r = measure();
        CHECK(!r.have_arm); /* fail before dereferencing an oversized prefix */
        answer.hit.decoy = NULL; answer.hit.decoy_len = 0;
    }

    /* A raw layer that failed its own self-check is a LOCAL defect, not a
     * DPI property (spec §9.9): the original search did not run, so the
     * adapter must not claim it, and the scheduler may ask its datapath
     * questions instead of failing the task. */
    memset(&answer, 0, sizeof answer);
    answer.verdict = D2K_DV_OPAQUE;
    answer.raw_selftest_failed = 1;
    r = measure();
    CHECK(r.verdict == D2K_V_OPAQUE && !r.have_arm && !r.owns_search);
    answer.raw_selftest_failed = 0;
    answer.raw_usable = 1;
    r = measure();
    CHECK(r.verdict == D2K_V_OPAQUE && r.owns_search); /* search ran, found nothing */
    /* nft-only router: no RST rule, the self-check (handshake only) passes,
     * every poison probe is cut by OUR kernel's RST. That empty search is a
     * local limitation (donor note 04.09), never «nothing to bypass». */
    rule_failed = 1;
    snprintf(answer.reason, sizeof answer.reason, "содержимое важно");
    r = measure();
    CHECK(r.verdict == D2K_V_OPAQUE && !r.have_arm && !r.owns_search);
    CHECK(strstr(r.reason, "RST") != NULL && strstr(r.reason, "не подавлен") != NULL);
    answer.verdict = D2K_DV_POISONABLE;
    answer.has_hit = 1;
    strcpy(answer.hit.name, "seqovl-1");
    answer.hit.seqovl = 1;
    r = measure();
    CHECK(r.have_arm && r.owns_search); /* a hit is a finished search */
    rule_failed = 0;
    memset(&answer, 0, sizeof answer);
    /* Отказ правила случился ДО этого прогона (счётчик на старте уже 1): пустой
       поиск этого прогона честный и владеет поиском — прошлый отказ не метит
       прогоны навсегда (ревью задачи 49). */
    rule_failed = 1;
    answer.rst_fail_base = 1;
    answer.raw_usable = 1;
    snprintf(answer.reason, sizeof answer.reason, "содержимое важно");
    r = measure();
    CHECK(r.owns_search && strstr(r.reason, "не подавлен") == NULL);
    rule_failed = 0;
    memset(&answer, 0, sizeof answer);
    /* Финальное ревью detect, I1: прогон, который сырым слоем не ходил вовсе,
       пометку «RST не подавлен» не получает и владения поиском не теряет —
       даже если счётчик отказов потока почему-то сдвинулся. */
    rule_failed = 1;
    dialled = 0;
    answer.raw_usable = 1;
    snprintf(answer.reason, sizeof answer.reason, "содержимое важно");
    r = measure();
    CHECK(r.owns_search && strstr(r.reason, "не подавлен") == NULL);
    rule_failed = 0;
    dialled = 1;
    memset(&answer, 0, sizeof answer);

    /* Базовый вопрос донора отдельно (задача 32): тот же измеритель, та же
       метка/повторы/контроль, но без ответного направления и сырого слоя;
       блокировка — ни одного прохода и ни одной ошибки транспорта. */
    progress_reset();
    r = measure_base(0, 2, "");
    CHECK(r.base_blocked && r.verdict == D2K_V_INCONCLUSIVE && r.probes == 2);
    CHECK(seen_name[0] == '\0' && seen.no_raw == 1);
    CHECK(seen.mark == 0x2d && seen.repeats == 2 && seen.control.len == 3);
    CHECK(base_stop_before == 0 && base_stop_other == 0 && base_stop_after == 1);
    /* Базовый вопрос тоже отдаёт ход, не теряя своей остановки на "whole". */
    CHECK(progress_calls == 2 && progress_probes == 6 && strcmp(progress_last, "whole") == 0);
    r = measure_base(2, 0, "");
    CHECK(!r.base_blocked && r.verdict == D2K_V_CLEAR);
    r = measure_base(1, 1, "");
    CHECK(!r.base_blocked && r.verdict == D2K_V_FLAKY);
    CHECK(r.base.valid && r.base.repeats == 2 && r.base.pass == 1 && r.base.fail == 1);
    r = measure_base(0, 2, "connect: refused");
    CHECK(!r.base_blocked && r.verdict == D2K_V_UNREACHABLE);
    CHECK(r.base.valid && strcmp(r.base.err, "connect: refused") == 0);
    r = measure_base(0, 1, ""); /* брошен на втором повторе */
    CHECK(!r.base_blocked && r.verdict == D2K_V_INCONCLUSIVE && !r.base.valid);
    {
        /* Полный прогон с ответом базы: подсказка доходит до измерителя. */
        uint8_t hello[] = {0x16, 0x03};
        d2k_hello tr = {hello, sizeof hello}, none = {0};
        d2k_base_seed seed;
        memset(&seed, 0, sizeof seed);
        seed.valid = 1; seed.repeats = 2; seed.pass = 0; seed.fail = 2;
        memset(&answer, 0, sizeof answer);
        answer.verdict = D2K_DV_PREFIX;
        progress_reset();
        r = d2k_detect_sched_tcp_seeded("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321, NULL, &seed);
        CHECK(seen.seed_whole == 1 && seen.seed_repeats == 2 && seen.seed_pass == 0 &&
              seen.seed_fail == 2 && r.verdict == D2K_V_PREFIX);
        /* Полный прогон отдаёт ход планировщику: каждый вопрос с его зондами. */
        CHECK(seen.on_obs != NULL);
        /* Задача 49: "whole" с ответом базы — без зондов (они прошлого прогона). */
        CHECK(progress_calls == 2 && progress_probes == 3 && strcmp(progress_last, "whole") == 0);
        progress_reset();
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321);
        CHECK(seen.seed_whole == 0);
        CHECK(progress_calls == 2 && progress_probes == 6 && strcmp(progress_last, "whole") == 0);
    }
    memset(&answer, 0, sizeof answer);

    memset(&p, 0, sizeof p);
    p.ttl = 8;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.repeats == 1 && arm.ttl == 8); /* TTL-only poison still emits a fake */
    p.ttl = 0;
    p.seq_shift = -66000;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.repeats == 1 && arm.seq_out);
    p.seq_shift = -123;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.seq_shift = 0;
    p.disorder = 1; p.disorder_pos = 2;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.disorder && arm.disorder_pos == 2);
    p.disorder = 0; p.disorder_pos = 0;
    p.syn_data = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.syn_data = 0; p.oob = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.oob = 0; p.md5 = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    if (failures) { return 1; }
    puts("bridge: scheduler adapter contracts passed");
    return 0;
}
