#include "d2k_update.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static d2ku_rc snapshot(void *arg, d2ku_clock_sample *out)
{ *out = *(d2ku_clock_sample *)arg; return D2KU_OK; }

static d2ku_clock_sample sample(int32_t date, unsigned minute)
{
    d2ku_clock_sample s = {0};
    s.utc_seconds = 1791075600; s.mono_ms = 1000;
    s.local_date = date; s.local_minute = minute; s.synchronized = 1;
    strcpy(s.boot_id, "boot-a"); strcpy(s.timezone, "MSK-3");
    return s;
}

static void schedule_boundaries(void)
{
    d2ku_policy p = {0}; d2ku_clock_sample s = sample(20261004, 179);
    d2ku_clock c = {0}; c.arg = &s; c.snapshot = snapshot;
    p.enabled = 1;
    assert(d2ku_select_minute(&p, 20261004, 0) == D2KU_OK);
    assert(d2ku_auto_due(&p, &c) == 0); /* 02:59 */
    s.local_minute = 180; assert(d2ku_auto_due(&p, &c) == 1);
    s.local_minute = 299; assert(d2ku_auto_due(&p, &c) == 1);
    s.local_minute = 300; assert(d2ku_auto_due(&p, &c) == 0);
    s.local_minute = 250;
    assert(d2ku_select_minute(&p, 20261004, 119) == D2KU_OK);
    assert(p.selected_minute == 180); /* today's persisted choice survives */
    assert(d2ku_select_minute(&p, 20261005, 119) == D2KU_OK);
    s.local_date = 20261005; s.local_minute = 298;
    assert(d2ku_auto_due(&p, &c) == 0);
    s.local_minute = 299; assert(d2ku_auto_due(&p, &c) == 1);
    assert(d2ku_select_minute(&p, 20261005, 120) == D2KU_INVALID);
    assert(d2ku_select_minute(&p, 20260230, 0) == D2KU_INVALID);
    assert(d2ku_select_minute(&p, 20261004, 0) == D2KU_TIME);
}

static void attempts_boot_dst_and_download(void)
{
    d2ku_policy p = {0}; d2ku_clock_sample s = sample(20261025, 270);
    d2ku_clock c = {0}; c.arg = &s; c.snapshot = snapshot; p.enabled = 1;
    assert(d2ku_select_minute(&p, 20261025, 30) == D2KU_OK);
    /* Boot 04:30, after choice, permits catch-up. */
    assert(d2ku_auto_due(&p, &c) == 1);
    /* Download finishing after 05:00 must not begin/consume install. */
    s.local_minute = 300;
    assert(d2ku_mark_auto_attempt(&p, &c) == D2KU_BUSY);
    assert(p.last_attempt_date == 0);
    s.local_minute = 299;
    assert(d2ku_mark_auto_attempt(&p, &c) == D2KU_OK);
    assert(p.last_attempt_date == 20261025);
    assert(d2ku_auto_due(&p, &c) == 0);
    s.local_minute = 210; /* repeated hour / backward wall */
    s.utc_seconds -= 3600;
    assert(d2ku_auto_due(&p, &c) == 0);
    strcpy(s.boot_id, "boot-b"); s.mono_ms = 0;
    assert(d2ku_auto_due(&p, &c) == 0);
    s.local_date = 20261024;
    assert(d2ku_auto_due(&p, &c) == 0);
    assert(d2ku_select_minute(&p, 20261024, 0) == D2KU_TIME);
    s.local_date = 20261026;
    assert(d2ku_select_minute(&p, 20261026, 0) == D2KU_OK);
    s.local_minute = 270; assert(d2ku_auto_due(&p, &c) == 1);
    p.enabled = 0; assert(d2ku_auto_due(&p, &c) == 0);
    /* DST forward skips selected minute; catch up within same window. */
    p.enabled = 1; s.local_date = 20270328; s.local_minute = 240;
    assert(d2ku_select_minute(&p, 20270328, 30) == D2KU_OK);
    assert(d2ku_auto_due(&p, &c) == 1);
    s.local_minute = 301; assert(d2ku_auto_due(&p, &c) == 0);
}

static void trusted_time(void)
{
    d2ku_policy p = {0}; d2ku_clock_sample s = sample(20261004, 240), out;
    d2ku_clock c = {0}; c.arg = &s; c.snapshot = snapshot; p.enabled = 1;
    c.build_timestamp = 1791075500; c.last_accepted_timestamp = 1791075600;
    assert(d2ku_select_minute(&p, 20261004, 0) == D2KU_OK);
    assert(d2ku_read_clock(&c, &out) == D2KU_OK);
    s.synchronized = 0;
    assert(d2ku_read_clock(&c, &out) == D2KU_TIME);
    assert(d2ku_auto_due(&p, &c) == 0);
    assert(d2ku_mark_auto_attempt(&p, &c) == D2KU_TIME);
    s.synchronized = 1; s.utc_seconds = 1791075599;
    assert(d2ku_read_clock(&c, &out) == D2KU_TIME);
    c.last_accepted_timestamp = 0; s.utc_seconds = 1791075499;
    assert(d2ku_read_clock(&c, &out) == D2KU_TIME);
    s.utc_seconds = 1791075600; s.local_date = 20260229;
    assert(d2ku_read_clock(&c, &out) == D2KU_TIME);
    s.local_date = 20280229;
    assert(d2ku_read_clock(&c, &out) == D2KU_OK);
    s.local_minute = 1440;
    assert(d2ku_read_clock(&c, &out) == D2KU_TIME);
    c.snapshot = NULL;
    assert(d2ku_read_clock(&c, &out) == D2KU_TIME);
}

static void cache_and_quarantine(void)
{
    d2ku_status st = {0}; d2ku_clock_sample s = sample(20261004, 120);
    d2ku_policy p = {0}; unsigned char hash[32] = {1}, other[32] = {2};
    assert(d2ku_check_due(&st, 0, 0) == 1);
    assert(d2ku_cache_record(&st, &s, D2KU_OK) == D2KU_OK);
    assert(d2ku_check_due(&st, 900000, 0) == 0); /* age 899s */
    assert(d2ku_check_due(&st, 900000, 1) == 1);
    assert(d2ku_check_due(&st, 901000, 0) == 1); /* exactly 900s */
    assert(d2ku_check_due(&st, 999, 0) == 1); /* backward monotonic */
    st.check_in_flight = 1;
    assert(d2ku_check_due(&st, 901000, 1) == 0); /* force joins */
    st.check_in_flight = 0;
    s.mono_ms = 2000; s.utc_seconds++;
    assert(d2ku_cache_record(&st, &s, D2KU_NETWORK) == D2KU_OK);
    assert(st.check_result == D2KU_NETWORK);
    assert(st.last_success_utc == 1791075600);
    assert(d2ku_check_due(&st, 2001, 0) == 0); /* error cache */
    strcpy(s.boot_id, "boot-b"); s.mono_ms = 2001;
    d2ku_cache_observe(&st, &s);
    assert(d2ku_check_due(&st, 2001, 0) == 1);
    assert(d2ku_cache_record(&st, &s, D2KU_TIME) == D2KU_OK);
    assert(d2ku_check_due(&st, 2002, 0) == 0);
    s.boot_id[0] = '\0';
    d2ku_cache_observe(&st, &s);
    assert(d2ku_check_due(&st, 2002, 0) == 1);
    assert(d2ku_cache_record(&st, &s, D2KU_OK) == D2KU_INVALID);
    p.enabled = 0; /* disabled does not affect checks */
    assert(d2ku_check_due(&st, 2002, 1) == 1);
    p.enabled = 1;
    assert(d2ku_auto_release_allowed(&p, hash) == 1);
    p.has_quarantined_release = 1;
    memcpy(p.quarantined_release_sha256, hash, 32);
    assert(d2ku_auto_release_allowed(&p, hash) == 0);
    assert(d2ku_auto_release_allowed(&p, other) == 1);
    p.enabled = 0;
    assert(d2ku_auto_release_allowed(&p, other) == 0);
}

int main(void)
{
    schedule_boundaries(); attempts_boot_dst_and_download(); trusted_time();
    cache_and_quarantine(); puts("schedule tests: ok"); return 0;
}
