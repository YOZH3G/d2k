#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "startup.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* Maintenance serializes the absent-marker check with lifetime ownership.
 * Caller retains both through startup publication, then keeps ownership until
 * its worker/groups and public socket are gone. Stable boot needs no curl. */
d2ku_rc d2ku_startup_claim(d2ku_ctx *ctx, const char *name, int *maintenance,
                           int *ownership) {
  if (!ctx || !name || !maintenance || !ownership ||
      (strcmp(name, "daemon.lock") && strcmp(name, "supervisor.lock")))
    return D2KU_INVALID;
  *maintenance = *ownership = -1;
  int guard = -1;
  d2ku_rc rc = d2ku_maintenance_lock(ctx, &guard);
  if (rc != D2KU_OK)
    return rc;
  struct stat st;
  if (!fstatat(ctx->root_dirfd, "update-state/lifecycle", &st,
               AT_SYMLINK_NOFOLLOW))
    rc = D2KU_BUSY;
  else if (errno != ENOENT)
    rc = D2KU_IO;
  int dir = -1, owner = -1;
  if (rc == D2KU_OK) {
    dir = openat(ctx->root_dirfd, "update-state",
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0)
      rc = D2KU_IO;
  }
  if (rc == D2KU_OK) {
    owner = openat(dir, name, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (owner < 0)
      rc = D2KU_IO;
    else if (fstat(owner, &st) || !S_ISREG(st.st_mode) ||
             st.st_uid != geteuid() || (st.st_mode & 077) || st.st_nlink != 1)
      rc = D2KU_INVALID;
    else if (flock(owner, LOCK_EX | LOCK_NB))
      rc = errno == EWOULDBLOCK || errno == EAGAIN ? D2KU_BUSY : D2KU_IO;
  }
  if (dir >= 0)
    close(dir);
  if (rc != D2KU_OK) {
    if (owner >= 0)
      close(owner);
    d2ku_maintenance_unlock(guard);
    return rc;
  }
  *maintenance = guard;
  *ownership = owner;
  return D2KU_OK;
}
