#ifndef D2KU_TRANSACTION_INTERNAL_H
#define D2KU_TRANSACTION_INTERNAL_H
#include "d2k_update.h"
d2ku_rc d2ku_tx_recover_locked(d2ku_ctx *, d2ku_status *);
d2ku_rc d2ku_tx_phase(d2ku_ctx *, d2ku_journal *, d2ku_phase);
d2ku_rc d2ku_tx_source_kind(d2ku_ctx *, const char *, d2ku_source_kind *);
d2ku_rc d2ku_tx_receipt(d2ku_ctx *, const char *, unsigned char hash[32]);
d2ku_rc d2ku_tx_current(d2ku_ctx *, char id[D2KU_ID_MAX + 1]);
d2ku_rc d2ku_boot_group(d2ku_ctx *, pid_t, int registering);
d2ku_rc d2ku_group_cleanup(pid_t);
#endif
