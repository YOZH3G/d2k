/* Private Linux container only. ROOT SIGNED_FIXTURE; production transaction,
 * Ed25519 verification, service adapter and real clocks (no health mocks). */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "../src/legacy_runtime.h"
#include "../src/transaction_internal.h"
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static d2ku_rc (*real_sample)(void *, d2ku_clock_sample *);
static d2ku_rc sample(void *p, d2ku_clock_sample *s) {
  d2ku_rc r = real_sample(p, s);
  s->utc_seconds = time(NULL);
  s->synchronized = 1;
  s->local_date = 20261005;
  s->local_minute = 600;
  strcpy(s->timezone, "UTC");
  return r;
}
static d2ku_rc wall(void *p, int64_t *n) {
  (void)p;
  *n = time(NULL);
  return D2KU_OK;
}
static void *readfile(int d, const char *name, size_t *n) {
  int f = openat(d, name, O_RDONLY);
  assert(f >= 0);
  struct stat st;
  assert(!fstat(f, &st));
  *n = (size_t)st.st_size;
  void *b = malloc(*n + 1);
  assert(b);
  assert(read(f, b, *n) == (ssize_t)*n);
  close(f);
  return b;
}
int main(int argc, char **argv) {
  assert(argc == 3 && getenv("D2KU_LEGACY_LAB"));
  d2ku_ctx c = {.root_dirfd = open(argv[1], O_RDONLY | O_DIRECTORY),
                .health_runtime_dirfd = -1,
                .maintenance_lock_fd = -1,
                .wire_version = 13,
                .state_version = 1,
                .updater_version = 1};
  assert(c.root_dirfd >= 0);
  strcpy(c.abi, "arm64");
  d2ku_service_config sc;
  assert(d2ku_service_configure(&c, argv[1], &sc) == D2KU_OK);
  assert(d2ku_service_recovery_context(&c, sc.runtime) == D2KU_OK);
  c.clock.wall = wall;
  real_sample = c.clock.snapshot;
  c.clock.snapshot = sample;
  int d = open(argv[2], O_RDONLY | O_DIRECTORY);
  assert(d >= 0);
  size_t n;
  void *b = readfile(d, "TEST-public", &n);
  assert(n == 32);
  memcpy(c.trust[0].public_key, b, 32);
  free(b);
  c.trust_count = 1;
  c.trust[0].not_before = time(NULL) - 3600;
  c.trust[0].not_after = time(NULL) + 3600;
  unsigned char sig[64];
  b = readfile(d, "index.json.sig", &n);
  assert(n == 64);
  memcpy(sig, b, 64);
  free(b);
  b = readfile(d, "index.json", &n);
  d2ku_index ix;
  assert(d2ku_verify_index(&c, b, n, sig, &ix) == D2KU_OK);
  free(b);
  b = readfile(d, "manifest.json.sig", &n);
  assert(n == 64);
  memcpy(sig, b, 64);
  free(b);
  b = readfile(d, "manifest.json", &n);
  d2ku_manifest *m = malloc(sizeof *m);
  assert(m);
  assert(d2ku_verify_selected_manifest(&c, &ix, b, n, sig, m) == D2KU_OK);
  free(b);
  d2ku_persistent_state p = {.schema = 1,
                             .sequence = 1,
                             .has_accepted_index = 1,
                             .accepted_sequence = ix.sequence,
                             .trust_count = 1};
  p.trust[0] = c.trust[0];
  memcpy(p.accepted_index_sha256, ix.document_sha256, 32);
  assert(d2ku_persistent_store(&c, &p) == D2KU_OK);
  c.has_accepted_index = 1;
  c.accepted_sequence = ix.sequence;
  memcpy(c.accepted_index_sha256, ix.document_sha256, 32);
  d2ku_request r = {.command = D2KU_CMD_INSTALL,
                    .archive_fd = openat(d, "candidate.tar", O_RDONLY),
                    .index = &ix,
                    .manifest = m};
  strcpy(r.transaction_id, "legacy-first-signed");
  strcpy(r.release_id, m->release_id);
  memcpy(r.manifest_sha256, m->document_sha256, 32);
  assert(d2ku_tx_current(&c, r.expected_release_id) == D2KU_OK);
  assert(d2ku_tx_receipt(&c, r.expected_release_id,
                         r.expected_manifest_sha256) == D2KU_OK);
  d2ku_status status = {0};
  d2ku_rc rc = d2ku_install(&c, &r, &status);
  fprintf(stderr, "install returned %d\n", rc);
  d2ku_journal j;
  assert(d2ku_journal_load(&c, &j) == D2KU_OK);
  fprintf(
      stderr,
      "signed transition rc=%d phase=%d failure=%d recovery=%d snapshot=%d\n",
      rc, j.phase, j.failure_reason, j.recovery_reason, j.snapshot_ready);
  assert(rc == D2KU_HEALTH && j.phase == D2KU_ROLLED_BACK &&
         j.old_kind == D2KU_SOURCE_LEGACY_LOCAL && j.snapshot_ready);
  assert(!status.installation_healthy);
  assert(d2ku_persistent_load(&c, &p) == D2KU_OK &&
         p.policy.has_quarantined_release &&
         p.policy.quarantine_reason == D2KU_HEALTH);
  char current[65];
  assert(d2ku_tx_current(&c, current) == D2KU_OK &&
         !strcmp(current, r.expected_release_id));
  assert(d2ku_maintenance_lock(&c, &c.maintenance_lock_fd) == D2KU_OK);
  d2ku_journal check = j;
  check.phase = D2KU_VALIDATING;
  strcpy(check.new_release_id, j.old_release_id);
  check.new_release_id_len = j.old_release_id_len;
  d2ku_clock_sample clock;
  assert(c.clock.snapshot(c.clock.arg, &clock) == D2KU_OK);
  strcpy(check.progress_boot_id, clock.boot_id);
  check.progress_boot_id_len = strlen(clock.boot_id);
  d2ku_status observed = {.health_observing = 1};
  strcpy(observed.health_release, "previous-candidate");
  observed.health_pid[0] = 1;
  assert(d2ku_legacy_health(&c, &check, &observed) == D2KU_OK);
  /* A typed old source never lets an ordinary signed target use weak health. */
  d2ku_status strict = {0};
  assert(d2ku_health(&c, &check, &strict) != D2KU_OK);
  check.new_release_id[0] = 'X';
  assert(d2ku_legacy_health(&c, &check, &observed) == D2KU_INVALID);
  strcpy(check.new_release_id, j.old_release_id);
  const char *pidfiles[] = {"d2kd.pid", "d2k.pid"};
  for (unsigned k = 0; k < 2; k++) {
    pid_t pid;
    assert(d2ku_legacy_pid(&sc, pidfiles[k], &pid) == 1);
    assert(!kill(pid, SIGSTOP));
    struct timespec pause = {0, 50000000};
    nanosleep(&pause, NULL);
    memset(&observed, 0, sizeof observed);
    assert(d2ku_legacy_health(&c, &check, &observed) == D2KU_HEALTH);
    assert(!kill(pid, SIGCONT));
  }
  pid_t rule = fork();
  assert(rule >= 0);
  if (!rule) {
    execlp("iptables", "iptables", "-t", "mangle", "-F", "D2K_OUT",
           (char *)NULL);
    _exit(127);
  }
  int w;
  assert(waitpid(rule, &w, 0) == rule && WIFEXITED(w) && !WEXITSTATUS(w));
  memset(&observed, 0, sizeof observed);
  assert(d2ku_legacy_health(&c, &check, &observed) == D2KU_HEALTH);
  close(c.maintenance_lock_fd);
  c.maintenance_lock_fd = -1;
  puts("legacy negative health: frozen datapath/controller, missing own rules, "
       "wrong target type and strict new-runtime health: PASS");
  puts("verified signed first target -> failed start -> real wire12 recovery, "
       "120s readiness and quarantine: PASS");
  fflush(stdout);
  return 0;
}
