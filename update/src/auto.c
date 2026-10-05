#include "d2k_update.h"
#include <string.h>
d2ku_rc d2ku_auto_reserve(d2ku_ctx *c, const d2ku_request *r) {
  if (!c || !r || !r->automatic || !r->transaction_id[0] || !r->release_id[0])
    return D2KU_INVALID;
  int lock = -1;
  d2ku_rc rc = d2ku_maintenance_lock(c, &lock);
  if (rc != D2KU_OK)
    return rc;
  d2ku_persistent_state p;
  rc = d2ku_persistent_load(c, &p);
  if (rc == D2KU_OK &&
      (!d2ku_auto_due(&p.policy, &c->clock) ||
       !d2ku_auto_release_allowed(&p.policy, r->manifest_sha256)))
    rc = D2KU_BUSY;
  if (rc == D2KU_OK)
    rc = d2ku_mark_auto_attempt(&p.policy, &c->clock);
  if (rc == D2KU_OK) {
    p.sequence++;
    memcpy(p.auto_operation, r->transaction_id, sizeof p.auto_operation);
    memcpy(p.auto_release, r->release_id, sizeof p.auto_release);
    memcpy(p.auto_manifest_sha256, r->manifest_sha256, 32);
    rc = d2ku_persistent_store(c, &p);
  }
  d2ku_maintenance_unlock(lock);
  return rc;
}
d2ku_rc d2ku_auto_reservation_valid(d2ku_ctx *c, const d2ku_request *r) {
  d2ku_clock_sample now;
  d2ku_rc rc = d2ku_read_clock(&c->clock, &now);
  if (rc != D2KU_OK)
    return rc;
  d2ku_persistent_state p;
  rc = d2ku_persistent_load(c, &p);
  if (rc != D2KU_OK)
    return rc;
  if (p.policy.last_attempt_date != now.local_date ||
      p.policy.selected_date != now.local_date ||
      now.local_minute < p.policy.selected_minute || now.local_minute >= 300)
    return D2KU_TIME;
  if (!p.auto_operation[0] || strcmp(p.auto_operation, r->transaction_id) ||
      strcmp(p.auto_release, r->release_id) ||
      memcmp(p.auto_manifest_sha256, r->manifest_sha256, 32) ||
      !d2ku_auto_release_allowed(&p.policy, r->manifest_sha256))
    return D2KU_BUSY;
  return D2KU_OK;
}
