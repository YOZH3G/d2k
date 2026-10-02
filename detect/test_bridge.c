/* Contract tests for the production scheduler adapter, without network.
 * The classifier itself is exercised by test_tree; here its input/output
 * is intercepted so a correct classifier cannot hide a broken adapter. */
#include "d2k_detect.h"
#include "d2k_verdict.h"
#include <stdio.h>
#include <string.h>

d2k_vres d2k_detect_sched_tcp(const char *, uint16_t, d2k_hello, d2k_hello,
                             uint32_t, int, uint32_t, uint32_t);
int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);

static d2k_opts seen;
static d2k_result answer;
static int failures;
static char seen_name[96];
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
        /* No SNI in the capture: no name, so no response probe on an IP. */
        tr.bytes = (uint8_t *)"\x16\x03"; tr.len = 2;
        d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321);
        CHECK(seen_name[0] == '\0');
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
