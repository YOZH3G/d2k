#ifndef D2KU_LIFECYCLE_H
#define D2KU_LIFECYCLE_H
#include "d2k_update.h"
#define D2KU_HANDOFF_RC ((d2ku_rc)14)
#define D2KU_QUIESCED_RC ((d2ku_rc)15)
typedef struct {
  int stopped;
  pid_t worker;
  char boot[65], operation[65];
} d2ku_lifecycle;
d2ku_rc d2ku_lifecycle_load(d2ku_ctx *, d2ku_lifecycle *);
d2ku_rc d2ku_lifecycle_intent(d2ku_ctx *, const char *, pid_t);
d2ku_rc d2ku_lifecycle_ack(d2ku_ctx *, pid_t);
d2ku_rc d2ku_lifecycle_quiesce(d2ku_ctx *, const char *root);
#endif
