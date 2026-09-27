#include <stdint.h>
#include <stdio.h>

#include "d2k_udp_release.h"

static int fails;
#define CHECK(x, m) do { if (!(x)) { fprintf(stderr, "udp_release:%d: %s\n", __LINE__, m); fails++; } } while (0)

static uint32_t seen_ids[8], seen_verdicts[8];
static size_t seen;
static uint64_t done_token;
static int done_complete;
static size_t done_calls;
static size_t done_sent;
static uint64_t done_tokens[4];
static int done_completes[4];
static size_t done_sent_counts[4];
static uint32_t fail_id;
static int fail_once;

static int send_one(void *ctx, uint32_t id, uint32_t verdict) {
    (void)ctx;
    if (seen < sizeof seen_ids / sizeof seen_ids[0]) {
        seen_ids[seen] = id;
        seen_verdicts[seen] = verdict;
    }
    seen++;
    if (id == fail_id && fail_once) {
        fail_once = 0;
        return -1;
    }
    return 0;
}

static void note_done(void *ctx, const d2k_key *key, uint64_t token,
                      int complete, size_t sent) {
    (void)ctx;
    CHECK(key && key->proto == 17, "execution key lost");
    CHECK(sent == (complete ? 2u : sent), "sent count inconsistent");
    done_token = token;
    done_complete = complete;
    done_calls++;
    done_sent = sent;
    if (done_calls <= 4) {
        done_tokens[done_calls - 1] = token;
        done_completes[done_calls - 1] = complete;
        done_sent_counts[done_calls - 1] = sent;
    }
}

int main(void) {
    d2k_udp_release *q = d2k_udp_release_new(2, 4);
    uint32_t ids[] = {11, 12};
    uint32_t verdicts[] = {1, 0};
    d2k_key key = {1, 2, 3, 4, 17};
    CHECK(q != NULL, "allocation");
    CHECK(d2k_udp_release_enqueue(q, 100, ids, verdicts, 2, &key, 77) == 0,
          "delayed original batch accepted");
    CHECK(d2k_udp_release_next_ns(q) == 100,
          "next due time was not exposed");
    CHECK(d2k_udp_release_flush(q, 99, send_one, note_done, NULL) == 0,
          "batch released before its due time");
    CHECK(seen == 0, "early release escaped");
    CHECK(d2k_udp_release_next_ns(q) == 100,
          "early flush lost the pending due time");
    CHECK(d2k_udp_release_flush(q, 100, send_one, note_done, NULL) == 1,
          "due batch not released");
    CHECK(seen == 2 && seen_ids[0] == 11 && seen_ids[1] == 12,
          "original verdicts lost FIFO order");
    CHECK(seen_verdicts[0] == 1 && seen_verdicts[1] == 0,
          "original verdicts changed during release");
    CHECK(done_token == 77 && done_complete, "execution completion not reported");
    CHECK(d2k_udp_release_next_ns(q) == 0,
          "empty release queue still reports a deadline");

    seen = 0;
    done_calls = 0;
    fail_id = 12;
    fail_once = 1;
    CHECK(d2k_udp_release_enqueue(q, 200, ids, verdicts, 2, &key, 78) == 0,
          "second batch accepted");
    CHECK(d2k_udp_release_enqueue(q, 200, ids, verdicts, 2, &key, 79) == 0,
          "third batch accepted while capacity remains");
    CHECK(d2k_udp_release_flush(q, 200, send_one, note_done, NULL) == 2,
          "equal-deadline batches were not released");
    CHECK(done_calls == 2 && done_tokens[0] == 78 && !done_completes[0] &&
          done_sent_counts[0] == 1,
          "partial send was not reported with its token and count");
    fail_id = 0;
    CHECK(done_tokens[1] == 79 && done_completes[1],
          "same-deadline FIFO/second completion was lost");
    CHECK(d2k_udp_release_enqueue(q, 300, ids, verdicts, 2, &key, 80) == 0,
          "fourth batch accepted while capacity remains");
    CHECK(d2k_udp_release_enqueue(q, 301, ids, verdicts, 2, &key, 81) == 0,
          "fifth batch accepted while capacity remains");
    CHECK(d2k_udp_release_enqueue(q, 302, ids, verdicts, 2, &key, 82) != 0,
          "queue overflow accepted silently");
    d2k_udp_release_free(q);
    if (!fails) puts("UDP release: due ordering and bounded ownership passed");
    return fails != 0;
}
