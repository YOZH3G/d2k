#ifndef D2KU_LEGACY_H
#define D2KU_LEGACY_H
#include "d2k_update.h"
/* Local owner authorization; never accepted from signed/remote metadata. */
d2ku_rc d2ku_legacy_hash(int dirfd, unsigned char hash[32]);
d2ku_rc d2ku_legacy_create(d2ku_ctx *, int saved, int release, const char *id,
                           const char *abi, const unsigned char inventory[32]);
d2ku_rc d2ku_legacy_source(d2ku_ctx *, const char *id,
                           unsigned char inventory[32]);
d2ku_rc d2ku_legacy_admit(d2ku_ctx *, int saved, char abi[9]);
d2ku_rc d2ku_legacy_protocol(d2ku_ctx *, int saved);
d2ku_rc d2ku_legacy_bind(d2ku_ctx *, int saved);
d2ku_rc d2ku_legacy_greet(d2ku_service_config *, const char *);
d2ku_rc d2ku_legacy_started(d2ku_service_config *, const char *, uint64_t);
d2ku_rc d2ku_legacy_health(d2ku_ctx *, const d2ku_journal *, d2ku_status *);
d2ku_rc d2ku_legacy_before(d2ku_service_config *, const char *, const char *,
                           uint64_t);
d2ku_rc d2ku_legacy_after(d2ku_service_config *, const char *, const char *,
                          uint64_t);
#endif
