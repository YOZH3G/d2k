/* test_udp_path.c — NFQUEUE-ID ownership of the d2kd UDP hold wiring
 * (task 46, review round 1: I1, I2, M1, M2, M4).
 *
 * The session, hold and release modules are the real ones; only the kernel
 * verdict, the raw socket and the deferred queue are recorders.  The loop in
 * run_packet() is d2kd's: pre -> session -> post -> (late tail | verdict). */
#include <stdio.h>
#include <string.h>

#include "d2k_udp_path.h"
#include "d2k_nl.h"
#include "d2k_quichello.h"
#include "d2k_plan.h"
#include "d2k_plans.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "udp_path:%d: %s\n", __LINE__, m); fails++; } } while (0)

/* --- recorders ---------------------------------------------------------- */
#define MAXID 64
static unsigned verdicts_of[MAXID];
static uint32_t last_verdict[MAXID];
static unsigned sends_of[MAXID];          /* by the ID stamped in the packet */
static uint64_t send_at_of[MAXID];
static char order[256];
static size_t order_n;
static uint32_t verdict_fail_id;

static uint32_t id_in(const uint8_t *p, size_t n) {
    /* The test stamps the NFQUEUE ID into the IPv4 identification field. */
    return n >= 6 ? ((uint32_t)p[4] << 8 | p[5]) : 0;
}

static int rec_verdict(void *ctx, uint32_t id, uint32_t v) {
    (void)ctx;
    if (id < MAXID) { verdicts_of[id]++; last_verdict[id] = v; }
    if (order_n < sizeof order - 1) { order[order_n++] = v == D2K_NF_DROP ? 'd' : 'a';  order[order_n] = 0; }
    return id == verdict_fail_id ? -1 : 0;
}

static int rec_now(void *ctx, const uint8_t *p, size_t n) {
    (void)ctx;
    uint32_t id = id_in(p, n);
    if (id < MAXID) { sends_of[id]++; send_at_of[id] = 0; }
    if (order_n < sizeof order - 1) { order[order_n++] = 's';  order[order_n] = 0; }
    return 0;
}

static int rec_at(void *ctx, uint64_t at, const uint8_t *p, size_t n) {
    (void)ctx;
    uint32_t id = id_in(p, n);
    if (id < MAXID) { sends_of[id]++; send_at_of[id] = at; }
    if (order_n < sizeof order - 1) { order[order_n++] = 'q';  order[order_n] = 0; }
    return 0;
}

static void reset(void) {
    memset(verdicts_of, 0, sizeof verdicts_of);
    memset(last_verdict, 0, sizeof last_verdict);
    memset(sends_of, 0, sizeof sends_of);
    memset(send_at_of, 0, sizeof send_at_of);
    order_n = 0;
    order[0] = 0;
    verdict_fail_id = 0;
}

/* --- packets ------------------------------------------------------------ */
static size_t build(uint8_t *o, uint32_t id, uint16_t sport, const uint8_t *pay, size_t n) {
    size_t total = 28 + n;
    memset(o, 0, 28);
    o[0] = 0x45; o[2] = (uint8_t)(total >> 8); o[3] = (uint8_t)total;
    o[4] = (uint8_t)(id >> 8); o[5] = (uint8_t)id;
    o[8] = 64; o[9] = 17;
    o[12] = 192; o[13] = 168; o[14] = 1; o[15] = 67;
    o[16] = 57; o[17] = 144; o[18] = 248; o[19] = 192;
    o[20] = (uint8_t)(sport >> 8); o[21] = (uint8_t)sport;
    o[22] = 0x01; o[23] = 0xBB;
    o[24] = (uint8_t)((8 + n) >> 8); o[25] = (uint8_t)(8 + n);
    memcpy(o + 28, pay, n);
    return total;
}

/* A QUIC v1 Initial header that parses but does not decrypt: an unnamed flow
 * (no ClientHello can be assembled from it). */
static size_t unnamed_initial(uint8_t *pay, uint8_t salt) {
    size_t n = 1200;
    memset(pay, salt, n);
    pay[0] = 0xC3; pay[1] = 0; pay[2] = 0; pay[3] = 0; pay[4] = 1;
    pay[5] = 8; memset(pay + 6, 0x11, 8);   /* DCID */
    pay[14] = 0;                             /* SCID */
    pay[15] = 0;                             /* token */
    pay[16] = 0x40 | (uint8_t)((n - 18) >> 8); pay[17] = (uint8_t)(n - 18);
    return n;
}

static d2k_udp_out out;
static d2k_udp_path path;
static int last_replay_applied;

/* d2kd's per-packet order, minus plan execution (no plan installed). */
static int run_packet(d2k_session *s, uint32_t id, const uint8_t *pkt, size_t n,
                      uint64_t t, uint64_t seq) {
    uint8_t obuf[4096];
    d2k_key key;
    memset(&key, 0, sizeof key);
    if (seq) { path.seq = seq; }  /* 0: d2kd's own numbering (d2k_udp_path_read) */
    int fed = d2k_udp_path_pre(&path, id, pkt, n, t, &key);
    d2k_result r;
    d2k_session_packet(s, pkt, n, t, obuf, sizeof obuf, &r);
    d2k_udp_hold_batch b;
    int how = d2k_udp_path_post(&path, fed, &key, &r, &b);
    if (how == D2K_UDP_PATH_REPLAY) {
        d2k_session_packet(s, b.packets[0], b.len[0], t, obuf, sizeof obuf, &r);
        last_replay_applied = r.applied;
        (void)d2k_udp_out_batch(&out, &b, D2K_NF_ACCEPT, 0, t, t, path.seq);
    } else if (how == D2K_UDP_PATH_NORMAL || how == D2K_UDP_PATH_LOST) {
        int vf = 0;
        /* d2kd's gate: only a datagram the kernel would get plainly. */
        if (r.applied || r.verdict != D2K_VERDICT_ACCEPT ||
            !d2k_udp_out_late(&out, id, pkt, n, t, path.seq, &vf)) {
            (void)rec_verdict(NULL, id, D2K_NF_ACCEPT);
            /* d2kd: a plainly ACCEPTed datagram that opens a client flow. */
            if (!r.applied && r.verdict == D2K_VERDICT_ACCEPT) {
                (void)d2k_udp_path_passed(&path, pkt, n, t);
            }
        }
    }
    return how;
}

static d2k_session *fresh(d2k_udp_hold **h, d2k_udp_follow **f) {
    d2k_session *s = d2k_session_new(64, 32);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    *h = d2k_udp_hold_new();
    *f = d2k_udp_follow_new();
    memset(&out, 0, sizeof out);
    out.verdict = rec_verdict;
    out.send_now = rec_now;
    out.send_at = rec_at;
    out.follow = *f;
    out.can_resend = 1;
    memset(&path, 0, sizeof path);
    path.sess = s;
    path.hold = *h;
    path.out = &out;
    return s;
}

static void done(d2k_session *s, d2k_udp_hold *h, d2k_udp_follow *f) {
    d2k_udp_hold_free(h, NULL, NULL);
    d2k_udp_follow_free(f);
    d2k_session_free(s);
}

/* I1: an unnamed flow past the search window.  Every ID gets exactly one
 * verdict, and nothing already ACCEPTed is re-sent. */
static void test_unnamed_past_window(void) {
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    reset();
    uint8_t pay[1300], pkt[1400];
    for (uint32_t id = 1; id <= 12; id++) {
        size_t pn = unnamed_initial(pay, (uint8_t)id);
        size_t n = build(pkt, id, 50100, pay, pn);
        (void)run_packet(s, id, pkt, n, 1000 + id, id);
    }
    path.now_ns = 1000 + 13 + D2K_UDP_HOLD_WAIT_NS;
    path.seq = 99;
    (void)d2k_udp_hold_flush(h, path.now_ns, d2k_udp_path_release, &path);
    for (uint32_t id = 1; id <= 12; id++) {
        CHECK(verdicts_of[id] == 1, "exactly one verdict per ID");
        CHECK(sends_of[id] == 0 || last_verdict[id] == D2K_NF_DROP,
              "only a dropped copy may have been re-sent");
        CHECK(sends_of[id] <= 1, "never re-sent twice");
    }
    CHECK(last_verdict[1] == D2K_NF_ACCEPT && sends_of[1] == 0,
          "the held head goes to the kernel");
    CHECK(sends_of[9] == 0 && sends_of[12] == 0,
          "past the window the flow is not held, and not re-sent");
    CHECK(d2k_udp_hold_next_ns(h) == 0, "nothing left in the hold");
    done(s, h, f);
}

/* I1 guard: a packet the hold took but the session neither held nor declared
 * ready is reclaimed with its slot, never left owned behind an ACCEPT. */
static void test_reclaim_guard(void) {
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    reset();
    uint8_t pay[1300], pkt[1400];
    d2k_key key;
    size_t pn = unnamed_initial(pay, 1);
    size_t n = build(pkt, 1, 50200, pay, pn);
    CHECK(d2k_udp_path_pre(&path, 1, pkt, n, 2000, &key) == 1, "head fed");
    n = build(pkt, 2, 50200, pay, pn);
    CHECK(d2k_udp_path_pre(&path, 2, pkt, n, 2001, &key) == 1, "second fed");
    d2k_result r;
    memset(&r, 0, sizeof r);
    r.skipped = "early exit";
    d2k_udp_hold_batch b;
    CHECK(d2k_udp_path_post(&path, 1, &key, &r, &b) == D2K_UDP_PATH_RECLAIMED,
          "fed but neither held nor ready: reclaimed");
    CHECK(verdicts_of[1] == 1 && last_verdict[1] == D2K_NF_ACCEPT && sends_of[1] == 0,
          "reclaimed head: one ACCEPT");
    CHECK(verdicts_of[2] == 1 && last_verdict[2] == D2K_NF_DROP && sends_of[2] == 1,
          "reclaimed tail: re-sent once, copy dropped");
    CHECK(!strcmp(order, "asd"), "head verdict, then tail send, then its drop");
    CHECK(d2k_udp_hold_flush(h, 2000 + 2 * D2K_UDP_HOLD_WAIT_NS,
                             d2k_udp_path_release, &path) == 0 &&
          verdicts_of[1] == 1 && verdicts_of[2] == 1,
          "expiry finds nothing to release again");
    done(s, h, f);
}

/* Split ClientHello without a plan (requirement 1, unplanned batch), and the
 * late-tail window (I2). */
static void test_named_unplanned(void) {
    uint8_t probe[1600], head[2048], tail[2048], pkt[2200];
    size_t pl = 0, hn = 0, tn = 0;
    CHECK(d2k_quic_probe_initial("www.example.com", probe, sizeof probe, &pl) == 0 &&
          d2k_quic_hello_split(probe, pl, "www.example.com", head, sizeof head, &hn,
                               tail, sizeof tail, &tn) == 0,
          "split fixture");
    if (!hn || !tn) { return; }

    /* Tail first, then the datagram that completes the name: one batch. */
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    reset();
    size_t n = build(pkt, 1, 50300, tail, tn);
    int a = run_packet(s, 1, pkt, n, 3000, 1);
    n = build(pkt, 2, 50300, head, hn);
    int b = run_packet(s, 2, pkt, n, 3001, 1);
    CHECK(a == D2K_UDP_PATH_HELD && b == D2K_UDP_PATH_REPLAY, "held, then replayed");
    CHECK(verdicts_of[1] == 1 && last_verdict[1] == D2K_NF_ACCEPT && sends_of[1] == 0,
          "unplanned batch: head ACCEPT");
    CHECK(verdicts_of[2] == 1 && last_verdict[2] == D2K_NF_DROP && sends_of[2] == 1,
          "unplanned batch: tail re-sent, copy dropped");
    CHECK(!strcmp(order, "asd"), "verdict of the head before the tail leaves");

    /* Same receive batch: a 0-RTT queued behind the head is a late tail. */
    uint8_t zrtt[200];
    memset(zrtt, 0xD1, sizeof zrtt);
    n = build(pkt, 3, 50300, zrtt, sizeof zrtt);
    (void)run_packet(s, 3, pkt, n, 3001 + 10000000, 1);
    CHECK(verdicts_of[3] == 1 && last_verdict[3] == D2K_NF_DROP && sends_of[3] == 1,
          "queued in the head's receive batch: re-sent whatever the clock");
    /* Next batch, inside the clash window. */
    n = build(pkt, 4, 50300, zrtt, sizeof zrtt);
    (void)run_packet(s, 4, pkt, n, 3001 + D2K_UDP_FOLLOW_NS - 1, 2);
    CHECK(last_verdict[4] == D2K_NF_DROP && sends_of[4] == 1, "inside the window: re-sent");
    /* Next batch, past the window: the normal kernel path. */
    n = build(pkt, 5, 50300, zrtt, sizeof zrtt);
    (void)run_packet(s, 5, pkt, n, 3001 + D2K_UDP_FOLLOW_NS, 3);
    CHECK(verdicts_of[5] == 1 && last_verdict[5] == D2K_NF_ACCEPT && sends_of[5] == 0,
          "past the clash window a datagram goes to the kernel");
    CHECK(D2K_UDP_FOLLOW_NS <= UINT64_C(5000000), "window bounded at 5 ms");
    done(s, h, f);

    /* Name in the first datagram: the head is released alone and the queued
       datagram behind it follows it (field 03.10: lost 3 of 3 before). */
    s = fresh(&h, &f);
    reset();
    n = build(pkt, 1, 50301, probe, pl);
    a = run_packet(s, 1, pkt, n, 4000, 7);
    n = build(pkt, 2, 50301, zrtt, sizeof zrtt);
    b = run_packet(s, 2, pkt, n, 4001, 7);
    CHECK(a == D2K_UDP_PATH_REPLAY && b == D2K_UDP_PATH_NORMAL, "head alone, tail later");
    CHECK(last_verdict[1] == D2K_NF_ACCEPT && sends_of[1] == 0, "head ACCEPT");
    CHECK(verdicts_of[2] == 1 && last_verdict[2] == D2K_NF_DROP && sends_of[2] == 1,
          "tail outside the batch still follows the head");
    done(s, h, f);
}

/* M1: a late tail never overtakes a deferred owned head; M2: no tail ahead of
 * a head whose verdict failed. */
static void test_ordering_guards(void) {
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    uint8_t pay[100], pkt[200];
    d2k_udp_hold_batch b;
    memset(&b, 0, sizeof b);
    memset(pay, 0x55, sizeof pay);
    b.count = 2;
    b.ids[0] = 10; b.len[0] = build(b.packets[0], 10, 50400, pay, sizeof pay);
    b.ids[1] = 11; b.len[1] = build(b.packets[1], 11, 50400, pay, sizeof pay);

    reset();
    uint64_t now = 5000, at = 5000 + 20000000;
    CHECK(d2k_udp_out_batch(&out, &b, D2K_NF_DROP, 1, at, now, 3) == 0, "owned, deferred");
    CHECK(send_at_of[11] == at && last_verdict[11] == D2K_NF_DROP,
          "owned deferred: the tail waits behind the plan's emits");
    size_t n = build(pkt, 12, 50400, pay, sizeof pay);
    int vf = 0;
    CHECK(d2k_udp_out_late(&out, 12, pkt, n, now + 1000000, 4, &vf) == 1,
          "late tail of a deferred head matched (window counts from the head)");
    CHECK(sends_of[12] == 1 && send_at_of[12] == at && last_verdict[12] == D2K_NF_DROP,
          "late tail queued at the head's time, not sent ahead of it");

    reset();
    verdict_fail_id = 10;
    b.ids[0] = 10; b.ids[1] = 11;
    (void)d2k_udp_out_batch(&out, &b, D2K_NF_ACCEPT, 0, now, now, 5);
    CHECK(sends_of[11] == 0 && last_verdict[11] == D2K_NF_ACCEPT,
          "head verdict failed: the tail is ACCEPTed, not sent ahead of it");
    reset();
    verdict_fail_id = 10;
    (void)d2k_udp_out_batch(&out, &b, D2K_NF_DROP, 1, now, now, 6);
    CHECK(sends_of[11] == 1 && last_verdict[11] == D2K_NF_DROP,
          "owned head already left as the plan's emit: its tail still follows");

    /* Observe mode: nothing is re-sent, nothing marked. */
    reset();
    out.can_resend = 0;
    (void)d2k_udp_out_batch(&out, &b, D2K_NF_ACCEPT, 0, now, now, 7);
    CHECK(sends_of[11] == 0 && last_verdict[11] == D2K_NF_ACCEPT, "observe: plain ACCEPT");
    CHECK(d2k_udp_out_late(&out, 13, pkt, n, now, 7, &vf) == 0, "observe: no late path");
    done(s, h, f);
}

/* N2: an expiry on a poll wake with no read must not lend its read number to
 * the next read.  Follows d2kd's own numbering (read / expire). */
static void test_expiry_read_numbering(void) {
    for (int read_follows = 0; read_follows <= 1; read_follows++) {
        d2k_udp_hold *h; d2k_udp_follow *f;
        d2k_session *s = fresh(&h, &f);
        reset();
        uint8_t pay[1300], pkt[1400], late[200];
        memset(late, 0xD1, sizeof late);
        size_t pn = unnamed_initial(pay, 1);
        size_t n = build(pkt, 1, 50500, pay, pn);
        d2k_udp_path_read(&path, 1000);
        CHECK(run_packet(s, 1, pkt, n, 1000, 0) == D2K_UDP_PATH_HELD, "unnamed head held");
        uint64_t deadline = 1000 + D2K_UDP_HOLD_WAIT_NS;
        CHECK(d2k_udp_path_expire(&path, deadline, read_follows) == 1, "expired on the wake");
        CHECK(last_verdict[1] == D2K_NF_ACCEPT, "expired head ACCEPT");
        uint64_t later = deadline + 150000000;
        d2k_udp_path_read(&path, later);
        n = build(pkt, 2, 50500, late, sizeof late);
        (void)run_packet(s, 2, pkt, n, later, 0);
        CHECK(verdicts_of[2] == 1, "one verdict");
        if (read_follows) {
            CHECK(last_verdict[2] == D2K_NF_DROP && sends_of[2] == 1,
                  "read right after the expiry: queued before it, re-sent");
        } else {
            CHECK(last_verdict[2] == D2K_NF_ACCEPT && sends_of[2] == 0,
                  "a read 150 ms after a poll-wake expiry is NOT re-sent");
        }
        done(s, h, f);
    }
}

/* N1: a slot expiring inside the next feed must not turn an applied plan into
 * a reclaimed ACCEPT with nothing on the wire. */
static const uint8_t plan_bytes[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x00, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

static void test_expiry_inside_feed_keeps_plan(void) {
    uint8_t probe[1600], head[2048], tail[2048], pkt[2200];
    size_t pl = 0, hn = 0, tn = 0;
    CHECK(d2k_quic_probe_initial("www.example.com", probe, sizeof probe, &pl) == 0 &&
          d2k_quic_hello_split(probe, pl, "www.example.com", head, sizeof head, &hn,
                               tail, sizeof tail, &tn) == 0, "split fixture");
    if (!hn || !tn) { return; }
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    d2k_plan *p = NULL;
    char err[160];
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0 &&
          d2k_plantab_set_name_shaped(d2k_session_plans(s),
              (const uint8_t *)"www.example.com", 15, 1, p, D2K_PLAN_SHAPE_QUIC) == 0,
          "plan installed");
    reset();
    last_replay_applied = 0;
    size_t n = build(pkt, 1, 50600, tail, tn);
    d2k_udp_path_read(&path, 6000);
    CHECK(run_packet(s, 1, pkt, n, 6000, 0) == D2K_UDP_PATH_HELD, "tail held");
    /* The next datagram is read after the slot's deadline, before any
       top-of-loop flush caught it. */
    uint64_t t = 6000 + D2K_UDP_HOLD_WAIT_NS;
    d2k_udp_path_read(&path, t);
    n = build(pkt, 2, 50600, head, hn);
    int how = run_packet(s, 2, pkt, n, t, 0);
    CHECK(how == D2K_UDP_PATH_REPLAY, "the completing datagram is replayed, not reclaimed");
    CHECK(last_replay_applied, "the plan is applied through the replay path");
    CHECK(verdicts_of[1] == 1 && last_verdict[1] == D2K_NF_ACCEPT,
          "the expired tail was released once, before");
    CHECK(verdicts_of[2] == 1, "the replayed head got exactly one verdict");
    done(s, h, f);
}

/* N3: a late tail never overtakes a deferred head that is due but not yet
 * popped from the deferred queue; N4: wait without ownership is not HELD. */
static void test_due_head_and_unfed_wait(void) {
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    uint8_t pay[100], pkt[200];
    memset(pay, 0x55, sizeof pay);
    d2k_udp_hold_batch b;
    memset(&b, 0, sizeof b);
    b.count = 1;
    b.ids[0] = 20; b.len[0] = build(b.packets[0], 20, 50700, pay, sizeof pay);
    reset();
    uint64_t now = 7000, at = 7000 + 20000000;
    (void)d2k_udp_out_batch(&out, &b, D2K_NF_DROP, 1, at, now, 3);
    size_t n = build(pkt, 21, 50700, pay, sizeof pay);
    int vf = 0;
    CHECK(d2k_udp_out_late(&out, 21, pkt, n, at + 500000, 4, &vf) == 1, "late tail matched");
    CHECK(sends_of[21] == 1 && send_at_of[21] == at,
          "head due but not popped: the tail still queues behind it");

    d2k_result r;
    memset(&r, 0, sizeof r);
    r.udp_hold_wait = 1;
    d2k_key key;
    memset(&key, 0, sizeof key);
    CHECK(d2k_udp_path_post(&path, 0, &key, &r, &b) == D2K_UDP_PATH_NORMAL,
          "wait for a packet the hold does not own: the caller keeps the ID");
    done(s, h, f);
}

/* Field 03.10 after 4ed54d4: a burst of 4 datagrams whose first one is not a
 * QUIC Initial d2k can parse (long header, v1, random length field) is never
 * held; each datagram was ACCEPTed on its own and the 2nd..4th, which reached
 * conntrack while the 1st was still queued, were dropped as clashes (16 of 24
 * lost).  The first datagram of any client UDP flow opens the same clash
 * window as a released hold. */
static void test_unheld_opening_burst(void) {
    d2k_udp_hold *h; d2k_udp_follow *f;
    d2k_session *s = fresh(&h, &f);
    reset();
    uint8_t pay[1200], pkt[1300];
    for (uint32_t id = 1; id <= 4; id++) {
        memset(pay, (int)(0x30 + id), sizeof pay);
        pay[0] = 0xC5; pay[1] = 0; pay[2] = 0; pay[3] = 0; pay[4] = 1;
        pay[5] = 8; pay[16] = 0x7F; pay[17] = 0xFF; /* Length far past the datagram */
        size_t n = build(pkt, id, 50800, pay, sizeof pay);
        if (id == 1) { d2k_udp_path_read(&path, 8000); }
        CHECK(run_packet(s, id, pkt, n, 8000 + id * 100, 0) == D2K_UDP_PATH_NORMAL,
              "an unparseable Initial is not held");
    }
    CHECK(verdicts_of[1] == 1 && last_verdict[1] == D2K_NF_ACCEPT && sends_of[1] == 0,
          "the opening datagram goes to the kernel");
    for (uint32_t id = 2; id <= 4; id++) {
        CHECK(verdicts_of[id] == 1 && last_verdict[id] == D2K_NF_DROP && sends_of[id] == 1,
              "datagrams queued behind it follow it through the raw path");
    }
    CHECK(!strcmp(order, "asdsdsd"), "opening verdict first, then each follower");

    /* A later read past the window: the kernel path. */
    d2k_udp_path_read(&path, 8000 + 50000000);
    size_t n = build(pkt, 5, 50800, pay, sizeof pay);
    (void)run_packet(s, 5, pkt, n, 8000 + 50000000, 0);
    CHECK(last_verdict[5] == D2K_NF_ACCEPT && sends_of[5] == 0, "later datagram: kernel");

    /* The server's datagrams never open a client window. */
    uint8_t rev[200];
    memset(rev, 0x44, sizeof rev);
    n = build(pkt, 6, 50801, rev, sizeof rev);
    /* swap ends: 57.144.248.192:443 -> 192.168.1.67:50801 */
    uint8_t tmp[4]; memcpy(tmp, pkt + 12, 4); memcpy(pkt + 12, pkt + 16, 4); memcpy(pkt + 16, tmp, 4);
    uint8_t pt[2]; memcpy(pt, pkt + 20, 2); memcpy(pkt + 20, pkt + 22, 2); memcpy(pkt + 22, pt, 2);
    d2k_session_set_hook(s, D2K_HOOK_PREROUTING);
    d2k_udp_path_read(&path, 9000);
    (void)run_packet(s, 6, pkt, n, 9000, 0);
    n = build(pkt, 7, 50801, rev, sizeof rev);
    memcpy(tmp, pkt + 12, 4); memcpy(pkt + 12, pkt + 16, 4); memcpy(pkt + 16, tmp, 4);
    memcpy(pt, pkt + 20, 2); memcpy(pkt + 20, pkt + 22, 2); memcpy(pkt + 22, pt, 2);
    (void)run_packet(s, 7, pkt, n, 9001, 0);
    CHECK(sends_of[6] == 0 && sends_of[7] == 0 && last_verdict[7] == D2K_NF_ACCEPT,
          "server-side datagrams are never re-sent");
    done(s, h, f);
}

int main(void) {
    test_unheld_opening_burst();
    test_expiry_read_numbering();
    test_expiry_inside_feed_keeps_plan();
    test_due_head_and_unfed_wait();
    test_unnamed_past_window();
    test_reclaim_guard();
    test_named_unplanned();
    test_ordering_guards();
    if (!fails) puts("UDP path: one verdict per ID, tails behind the head, clash window passed");
    return fails != 0;
}
