#include "d2k_update.h"
#include <string.h>

static int date_valid(int32_t date)
{
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    int year = date / 10000, month = date / 100 % 100, day = date % 100;
    unsigned limit;
    if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1)
        return 0;
    limit = days[month - 1];
    if (month == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
        limit++;
    return (unsigned)day <= limit;
}

static int text_valid(const char *s, size_t cap)
{
    size_t i;
    if (!s[0]) return 0;
    for (i = 0; i < cap; i++) {
        if (!s[i]) return 1;
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e)
            return 0;
    }
    return 0;
}

d2ku_rc d2ku_read_clock(const d2ku_clock *clock, d2ku_clock_sample *out)
{
    d2ku_clock_sample s = {0};
    if (!clock || !out) return D2KU_INVALID;
    if (!clock->snapshot || clock->build_timestamp < 0 ||
        clock->last_accepted_timestamp < 0 ||
        clock->snapshot(clock->arg, &s) != D2KU_OK || s.synchronized != 1 ||
        s.utc_seconds < 0 || s.utc_seconds < clock->build_timestamp ||
        s.utc_seconds < clock->last_accepted_timestamp ||
        !date_valid(s.local_date) || s.local_minute >= 1440 ||
        !text_valid(s.boot_id, sizeof(s.boot_id)) ||
        !text_valid(s.timezone, sizeof(s.timezone))) return D2KU_TIME;
    *out = s;
    return D2KU_OK;
}

d2ku_rc d2ku_select_minute(d2ku_policy *policy, int32_t date, unsigned offset)
{
    if (!policy || !date_valid(date) || offset >= 120) return D2KU_INVALID;
    if (date < policy->selected_date || date < policy->last_attempt_date)
        return D2KU_TIME;
    if (date == policy->selected_date)
        return policy->selected_minute >= 180 && policy->selected_minute < 300
            ? D2KU_OK : D2KU_INVALID;
    policy->selected_date = date;
    policy->selected_minute = 180 + offset;
    return D2KU_OK;
}

static int due_at(const d2ku_policy *p, const d2ku_clock_sample *s)
{
    return p->enabled && p->selected_date == s->local_date &&
        s->local_date > p->last_attempt_date && p->selected_minute >= 180 &&
        p->selected_minute < 300 && s->local_minute >= p->selected_minute &&
        s->local_minute < 300;
}

int d2ku_auto_due(const d2ku_policy *policy, const d2ku_clock *clock)
{
    d2ku_clock_sample s;
    return policy && d2ku_read_clock(clock, &s) == D2KU_OK && due_at(policy, &s);
}

int d2ku_auto_release_allowed(const d2ku_policy *policy,
    const unsigned char hash[32])
{
    return policy && hash && policy->enabled &&
        (!policy->has_quarantined_release ||
         memcmp(policy->quarantined_release_sha256, hash, 32) != 0);
}

d2ku_rc d2ku_mark_auto_attempt(d2ku_policy *policy, const d2ku_clock *clock)
{
    d2ku_clock_sample s;
    d2ku_rc rc;
    if (!policy) return D2KU_INVALID;
    rc = d2ku_read_clock(clock, &s);
    if (rc != D2KU_OK) return rc;
    if (!due_at(policy, &s)) return D2KU_BUSY;
    policy->last_attempt_date = s.local_date;
    return D2KU_OK;
}

void d2ku_cache_observe(d2ku_status *status, const d2ku_clock_sample *sample)
{
    if (!status) return;
    if (!sample || !text_valid(sample->boot_id, sizeof(sample->boot_id))) {
        status->observed_boot_id[0] = '\0';
        status->has_check = 0;
        return;
    }
    if (strcmp(status->observed_boot_id, sample->boot_id) != 0)
        status->has_check = 0;
    memcpy(status->observed_boot_id, sample->boot_id, sizeof(sample->boot_id));
}

d2ku_rc d2ku_cache_record(d2ku_status *status, const d2ku_clock_sample *sample,
    d2ku_rc result)
{
    if (!status || !sample || !text_valid(sample->boot_id, sizeof(sample->boot_id)) ||
        result < D2KU_OK || result > D2KU_HEALTH ||
        (result == D2KU_OK && (sample->synchronized != 1 || sample->utc_seconds < 0)))
        return D2KU_INVALID;
    d2ku_cache_observe(status, sample);
    memcpy(status->checked_boot_id, sample->boot_id, sizeof(sample->boot_id));
    status->checked_mono_ms = sample->mono_ms;
    status->check_result = result;
    status->has_check = 1;
    if (result == D2KU_OK) {
        status->has_success = 1;
        status->last_success_utc = sample->utc_seconds;
    }
    return D2KU_OK;
}

int d2ku_check_due(const d2ku_status *status, uint64_t mono_ms, int force)
{
    if (!status) return 1;
    if (status->check_in_flight) return 0;
    return force || !status->has_check ||
        !text_valid(status->observed_boot_id, sizeof(status->observed_boot_id)) ||
        !text_valid(status->checked_boot_id, sizeof(status->checked_boot_id)) ||
        strcmp(status->observed_boot_id, status->checked_boot_id) != 0 ||
        mono_ms < status->checked_mono_ms ||
        mono_ms - status->checked_mono_ms >= D2KU_CHECK_TTL_MS;
}
