#include "transaction_fixture.h"
static unsigned minute = 240;
static int32_t date = 20261004;
static d2ku_rc sample_auto(void *p, d2ku_clock_sample *s) {
  d2ku_rc r = clock_sample(p, s);
  s->local_minute = minute;
  s->local_date = date;
  return r;
}
int main(void) {
  fixture f;
  setup(&f);
  f.c.clock.snapshot = sample_auto;
  f.c.sync_fd = sync_crash;
  d2ku_persistent_state p;
  assert(d2ku_persistent_load(&f.c, &p) == D2KU_OK);
  p.policy.enabled = 1;
  assert(d2ku_select_minute(&p.policy, date, 0) == D2KU_OK);
  p.sequence++;
  assert(d2ku_persistent_store(&f.c, &p) == D2KU_OK);
  f.r.automatic = 1;
  assert(d2ku_auto_reserve(&f.c, &f.r) == D2KU_OK);
  assert(d2ku_persistent_load(&f.c, &p) == D2KU_OK &&
         p.policy.last_attempt_date == date);
  assert(!strcmp(p.auto_operation, f.r.transaction_id));
  /* A failed download, daemon restart and a fresh operation do not restore the
   * date. */
  d2ku_ctx restart = f.c;
  d2ku_request next = f.r;
  strcpy(next.transaction_id, "next-operation");
  assert(d2ku_auto_reserve(&restart, &next) == D2KU_BUSY);
  minute = 301;
  assert(d2ku_auto_reservation_valid(&f.c, &f.r) == D2KU_TIME);
  minute = 240;
  date = 20261005;
  assert(d2ku_auto_reservation_valid(&restart, &f.r) != D2KU_OK);
  assert(d2ku_persistent_load(&restart, &p) == D2KU_OK);
  assert(d2ku_select_minute(&p.policy, date, 0) == D2KU_OK);
  p.sequence++;
  assert(d2ku_persistent_store(&restart, &p) == D2KU_OK);
  assert(d2ku_auto_reserve(&restart, &next) == D2KU_OK);
  f.r = next;
  strcpy(next.transaction_id, "wrong-owner");
  assert(d2ku_auto_reservation_valid(&f.c, &next) != D2KU_OK);
  assert(d2ku_auto_reservation_valid(&f.c, &f.r) == D2KU_OK);
  d2ku_status status = {0};
  assert(d2ku_install(&f.c, &f.r, &status) == D2KU_OK);
  assert(d2ku_persistent_load(&f.c, &p) == D2KU_OK &&
         p.policy.last_attempt_date == date);
  current(&f, "releases/B");
  check_file(f.c.root_dirfd, "state/knowledge", "candidate");
  cleanup(&f);
  setup(&f);
  assert(d2ku_persistent_load(&f.c, &p) == D2KU_OK);
  int32_t prior = p.policy.last_attempt_date;
  f.r.automatic = 0;
  assert(d2ku_install(&f.c, &f.r, &status) == D2KU_OK);
  assert(d2ku_persistent_load(&f.c, &p) == D2KU_OK &&
         p.policy.last_attempt_date == prior);
  cleanup(&f);
  puts("automatic reservation: durable predownload claim, reboot/no-repeat, "
       "owner/window validation: PASS");
}
