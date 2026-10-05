#ifndef D2KU_LEGACY_RUNTIME_H
#define D2KU_LEGACY_RUNTIME_H
#include "legacy.h"
int d2ku_legacy_argv(d2ku_service_config *, unsigned, size_t,
                     const char *const *);
int d2ku_legacy_pid(d2ku_service_config *, const char *, pid_t *);
uint64_t d2ku_legacy_ticks(pid_t, char *, pid_t *);
int d2ku_legacy_process(d2ku_service_config *, const char *, unsigned, pid_t,
                        int);
int d2ku_legacy_socket_owner(pid_t, unsigned long);
#endif
