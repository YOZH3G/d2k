/* Exercise production terminal/reset paths without creating a network worker. */
#define pthread_create summary_thread_create
#include "sched.c"
#undef pthread_create
#include "d2k_quic_arms.h"

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
    d2k_sched_free(s);
    if (fails) fprintf(stderr, "summary: %d failures\n", fails);
    return fails ? 1 : 0;
}
