#ifndef D2KU_STARTUP_H
#define D2KU_STARTUP_H
#include "d2k_update.h"
d2ku_rc d2ku_startup_claim(d2ku_ctx *, const char *lock_name, int *maintenance,
                           int *ownership);
/* Test-only deterministic pause before claiming lifetime ownership. */
#ifdef D2KU_TEST_STARTUP
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static inline void d2ku_startup_barrier(const char *role) {
  const char *wanted = getenv("D2KU_TEST_STARTUP_ROLE");
  const char *fds = getenv("D2KU_TEST_STARTUP_FDS");
  int ready, resume;
  char tail, byte = 'R';
  if (!wanted || strcmp(wanted, role) || !fds ||
      sscanf(fds, "%d:%d%c", &ready, &resume, &tail) != 2 || ready < 6 ||
      resume < 6)
    return;
  if (write(ready, &byte, 1) != 1)
    _exit(120);
  ssize_t n;
  do {
    n = read(resume, &byte, 1);
  } while (n < 0 && errno == EINTR);
  if (n != 1)
    _exit(121);
  close(ready);
  close(resume);
}
#else
#define d2ku_startup_barrier(role) ((void)(role))
#endif
#endif
