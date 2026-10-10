/* Raw measurement sends are the oracle, through the bridge and real executor.
 * Include the property catalog itself, as detect/test_repeats.c does: new
 * questions automatically enter this test without a second handwritten list. */
#include "d2k_compose.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_detect.h"
#include "../detect/props.c"
#include <stdio.h>
#include <string.h>

int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);
/* Scheduler reporting is unrelated to the pure bridge conversion. */
void d2k_sched_progress_note(const char *q, int pass, int fail) {
    (void)q; (void)pass; (void)fail;
}
static unsigned failures, cases, skipped;
#define BASE 10000u
#define REQUIRE(c) do { if (!(c)) { \
    fprintf(stderr, "%s len=%zu sni=%d:%d line=%d: %s\n", p.name, tr->len, \
            tr->sni_off, tr->sni_len, __LINE__, #c); failures++; goto done; \
} } while (0)

static void run_case(d2k_poison p, const d2k_trigger *tr, const uint8_t *decoy, size_t dn) {
    d2k_arm a;
    d2k_arm_input in = {0};
    d2k_sends sends;
    d2k_plan *plan = NULL;
    d2k_actions out = {0};
    d2k_pkt pkt = {0};
    uint8_t fake[2 * D2K_TRIGGER_MAX], seg[D2K_TRIGGER_MAX + 4096];
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    char text[8192], err[200];
    size_t tn = 0, index = 0;
    if (p.decoy_hello) { p.decoy = decoy; p.decoy_len = dn; }
    if (p.seqovl_exact) { p.seqovl = (int)dn; }
    int bridge_rc = d2k_arm_from_poison(&p, &a, err, sizeof err);
    /* MD5 is now required to traverse the complete measured-plan path. */
    REQUIRE(!p.md5 || bridge_rc == 0);
    /* oob (срочный байт) выражается планом «oob sni_middle 0f» и исполняется
       датапатом (поле 10.10.2026): мост обязан его принять, а не отвергнуть. */
    REQUIRE(!p.oob || bridge_rc == 0);
    if (bridge_rc == -1) {
        if (cases == 0) { printf("skip %s: %s\n", p.name, err); }
        skipped++; return;
    }
    /* oob ставит URG-байт в середину ИМЕНИ: без имени в приветствии плана нет
       (как перекрытие до конца имени). Для безымянного входа — пропуск. */
    if (p.oob && (tr->sni_len <= 1 || tr->sni_off <= 0)) { skipped++; return; }
    in.trigger_len = tr->len; in.sni_off = tr->sni_off; in.sni_len = tr->sni_len;
    /* No decoy pointer means padding, including non-hello overlap probes. */
    in.decoy_len = p.decoy_len;
    if (p.decoy_len) { memcpy(in.decoy, p.decoy, p.decoy_len); }
    REQUIRE(d2k_poison_sends(tr, &p, fake, sizeof fake, seg, sizeof seg, &sends) == 0);
    REQUIRE(d2k_arm_plan_measured(&a, &in, text, sizeof text) == 0);
    REQUIRE(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tn, err, sizeof err) == 0);
    REQUIRE(d2k_plan_load(tlv, tn, &plan, err, sizeof err) == 0);
    pkt.seq = BASE; pkt.payload = tr->payload; pkt.payload_len = tr->len;
    pkt.have_sni = tr->sni_len > 0; pkt.sni_off = tr->sni_off; pkt.sni_len = tr->sni_len;
    REQUIRE(d2k_plan_apply(plan, NULL, &pkt, &out) == 0);
    REQUIRE(out.fate == D2K_ORIG_DROP);
    /* oob: срочный байт на проводе задаётся URG-указателем, а не отдельной
       посылкой-фальшивкой, и его побайтную развёртку проверяет датапат своим
       тестом; здесь довольно того, что измеренный приём стал загружаемым
       планом, который датапат принял (fate DROP). */
    if (p.oob) { goto done; }
    for (size_t i = 0; i < sends.n; i++) {
        const d2k_send *s = &sends.v[i];
        for (size_t off = 0; off < s->len; ) {
            size_t n = s->len - off;
            if (n > D2K_ARM_SEGMENT_MAX) { n = D2K_ARM_SEGMENT_MAX; }
            REQUIRE(index < out.n);
            const d2k_emit *e = &out.v[index++];
            unsigned flags = (s->poison.badsum ? D2K_POISON_BADSUM : 0) |
                (s->poison.tcp_ts ? D2K_POISON_TCPTS_BACK : 0) |
                (s->poison.ip_id_zero ? D2K_POISON_IPID_ZERO : 0) |
                (s->poison.md5 ? D2K_POISON_MD5 : 0);
            REQUIRE(e->seq == (uint32_t)(BASE + s->seq_off + (int64_t)off));
            REQUIRE(e->seq_shift == s->poison.seq_shift);
            REQUIRE(e->kind == (s->kind == D2K_SEND_FAKE ? D2K_EMIT_FAKE : D2K_EMIT_PAYLOAD));
            REQUIRE(e->wire_profile == D2K_WIRE_DETECT_TCP);
            REQUIRE(e->poison == flags && e->ttl == s->poison.ttl);
            REQUIRE(e->delay_us == (off ? 0u : (unsigned)s->delay_ms * 1000u));
            REQUIRE(e->pre_len + e->len == n);
            REQUIRE(!e->pre_len || memcmp(e->pre, s->bytes + off, e->pre_len) == 0);
            REQUIRE(!e->len || memcmp(e->bytes, s->bytes + off + e->pre_len, e->len) == 0);
            off += n;
        }
    }
    REQUIRE(index == out.n);
    /* tail_ms is a wait before reading, with no subsequent wire send. */
done:
    d2k_actions_free(&out); d2k_plan_free(plan);
}

int main(void) {
    static const size_t lengths[] = {512, 1400, 1401, 2048};
    uint8_t decoy[681];
    int np;
    const d2k_poison *ps = d2k_poisons(&np);
    for (size_t i = 0; i < sizeof decoy; i++) { decoy[i] = (uint8_t)(i * 23 + 5); }
    for (size_t k = 0; k < sizeof lengths / sizeof lengths[0]; k++) {
        for (int named = 0; named < 2; named++) {
            d2k_trigger tr = {0};
            tr.len = lengths[k]; tr.sni_off = named ? (int)tr.len / 3 : 0;
            tr.sni_len = named ? 11 : 0;
            for (size_t i = 0; i < tr.len; i++) { tr.payload[i] = (uint8_t)(i * 13 + 3); }
            tr.payload[0] = 0x16; tr.payload[1] = 3; tr.payload[2] = 1;
            tr.payload[3] = (uint8_t)((tr.len - 5) >> 8); tr.payload[4] = (uint8_t)(tr.len - 5);
            tr.payload[5] = 1; tr.payload[6] = 0;
            tr.payload[7] = (uint8_t)((tr.len - 9) >> 8); tr.payload[8] = (uint8_t)(tr.len - 9);
            for (int i = 0; i < np; i++) { run_case(ps[i], &tr, decoy, sizeof decoy); }
            prop_probe pp[12]; int nq = prop_probes(pp, 12);
            for (int i = 0; i < nq; i++) {
                if (pp[i].set == SET_OVERLAP_SNI) {
                    if (!named) { continue; }
                    pp[i].p.seqovl = tr.sni_off + tr.sni_len;
                }
                run_case(pp[i].p, &tr, decoy, sizeof decoy);
            }
            cases++;
        }
    }
    prop_probe allq[12];
    int n_questions = prop_probes(allq, 12);
    printf("probe-plan: %u inputs, %d catalog hypotheses, %d questions, %u skipped, %u mismatches\n",
           cases, np, n_questions, skipped, failures);
    return failures ? 1 : 0;
}
