/* Isolated Linux container only. Arguments: BOOT ADAPTER.
 * Private flat bootstrap, actual runtime heartbeat/proc identity and external
 * lifecycle recovery of an interrupted first update. No host rules/network.
 * The platform script is a private process fixture; panel HTTP uses loopback.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define D2K_RELEASE_ID "flat-original"
#include "../../runtime/d2k_runtime.h"
#include "d2k_update.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
static int selfcheck(void) { return 0; }
static void put(const char *path, const char *data) {
  FILE *f = fopen(path, "w");
  assert(f);
  assert(fputs(data, f) >= 0);
  assert(!fclose(f));
  assert(!chmod(path, 0700));
}
static int invoke(const char *program, const char *root, const char *action,
                  const char *arg) {
  pid_t p = fork();
  assert(p >= 0);
  if (!p) {
    execl(program, program, "--root", root, action, arg, (char *)NULL);
    _exit(127);
  }
  int s;
  assert(waitpid(p, &s, 0) == p);
  return WIFEXITED(s) ? WEXITSTATUS(s) : 128 + WTERMSIG(s);
}
static void reap(void) {
  while (waitpid(-1, NULL, WNOHANG) > 0) {
  }
}
int main(int argc, char **argv) {
  int rc = d2k_runtime_offline(argc, argv, "fixture", selfcheck);
  if (rc >= 0)
    return rc;
  if (argc == 2 && !strcmp(argv[1], "serve")) {
    for (int i = 3; i <= 5; i++)
      assert(fcntl(i, F_GETFD) < 0 && errno == EBADF);
    assert(setsid() > 0);
    signal(SIGCHLD, SIG_IGN);
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    assert(fd >= 0);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(getenv("TEST_PORT"))),
        .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
    assert(!bind(fd, (void *)&a, sizeof a) && !listen(fd, 8));
    for (;;) {
      assert(!d2k_runtime_heartbeat(getenv("TEST_HEALTH"), NULL, 0, 1, 1));
      struct pollfd p = {fd, POLLIN, 0};
      if (poll(&p, 1, 100) > 0) {
        int s = accept(fd, NULL, NULL);
        if (s >= 0) {
          char b[1024];
          (void)read(s, b, sizeof b);
          const char response[] =
              "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
          (void)write(s, response, sizeof response - 1);
          close(s);
        }
      }
    }
  }
  assert(argc == 3);
  assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
  char temp[] = "/tmp/d2ku-first-recovery.XXXXXX";
  assert(mkdtemp(temp));
  char root[256], bundle[256], path[1024], cmd[4096], body[4096];
  snprintf(root, sizeof root, "%s/opt/d2k", temp);
  snprintf(bundle, sizeof bundle, "%s/bundle", temp);
  snprintf(cmd, sizeof cmd,
           "mkdir -p -m 700 %s/state %s/panel %s/files %s/update-state "
           "%s/opt/sbin %s/opt/etc/init.d %s/opt/etc/ndm/netfilter.d %s",
           root, root, root, root, temp, temp, temp, bundle);
  assert(!system(cmd));
  const char *bins[] = {"d2kd", "d2kc", "d2kpanel", "d2ktg"};
  for (unsigned i = 0; i < 4; i++) {
    snprintf(cmd, sizeof cmd, "cp %s %s/opt/sbin/%s", argv[0], temp, bins[i]);
    assert(!system(cmd));
  }
  const char *helpers[] = {
      "d2k-fw-heal.sh",        "d2k-tg-firewall.sh",
      "d2k-tg-watchdog.sh",    "d2k-ppe-deoffload.sh",
      "d2k-instagram-dns.sh",  "d2k-instagram-dns-scheduler.sh",
      "d2k-log-maintenance.sh"};
  for (unsigned i = 0; i < 7; i++) {
    snprintf(path, sizeof path, "%s/%s", root, helpers[i]);
    put(path, "#!/bin/sh\nexit 0\n");
    snprintf(path, sizeof path, "%s/%s", bundle, helpers[i]);
    put(path, "#!/bin/sh\nexit 0\n");
  }
  const char *inputs[] = {"S98d2k-update", "001-d2k.sh", "uninstall.sh"};
  for (unsigned i = 0; i < 3; i++) {
    snprintf(path, sizeof path, "%s/%s", bundle, inputs[i]);
    put(path, "#!/bin/sh\nexit 0\n");
  }
  snprintf(path, sizeof path, "%s/opt/etc/init.d/S99d2k", temp);
  put(path, "old init\n");
  snprintf(path, sizeof path, "%s/opt/etc/ndm/netfilter.d/001-d2k.sh", temp);
  put(path, "old ndm\n");
  snprintf(cmd, sizeof cmd,
           "cp %s %s/d2k-update-boot && cp %s %s/d2k-service-adapter", argv[1],
           bundle, argv[2], bundle);
  assert(!system(cmd));
  /* Stop waits until the process exits. Parent test reaps adopted children. */
  snprintf(path, sizeof path, "%s/S99d2k", bundle);
  put(path,
      "#!/bin/sh\ncase \"$2\" in\nstart) ( exec 3>&- 4>&- 5>&-; exec "
      "\"$D2K_RELEASE_ROOT/d2kpanel\" serve ) & echo $! > "
      "\"$D2K_DIR/panel.pid\"; sleep 1;;\nstop|remove-rules) if [ -f "
      "\"$D2K_DIR/panel.pid\" ]; then kill \"$(cat \"$D2K_DIR/panel.pid\")\" "
      "2>/dev/null || :; rm -f \"$D2K_DIR/panel.pid\"; fi;;\nheal) echo "
      "recovered > \"$D2K_DIR/external-finished\";;\n*) exit 1;;\nesac\n");
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  assert(sock >= 0);
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)}};
  assert(!bind(sock, (void *)&addr, sizeof addr));
  socklen_t z = sizeof addr;
  assert(!getsockname(sock, (void *)&addr, &z));
  unsigned port = ntohs(addr.sin_port);
  close(sock);
  char porttext[20];
  snprintf(porttext, sizeof porttext, "%u", port);
  setenv("TEST_PORT", porttext, 1);
  snprintf(path, sizeof path, "%s/runtime/d2kpanel.health", root);
  setenv("TEST_HEALTH", path, 1);
  snprintf(body, sizeof body,
           "MODE=off\nTG_ENABLED=0\nSTATE_DIR=%s/state\nD2K_RUNTIME_DIR=%s/"
           "runtime\nPANEL_LISTEN=127.0.0.1:%u\n",
           root, root, port);
  snprintf(path, sizeof path, "%s/config", root);
  put(path, body);
  snprintf(path, sizeof path, "%s/update-state/enabled", root);
  put(path, "4\n");
  assert(!chmod(path, 0600));
  assert(!invoke(argv[1], root, "--bootstrap", bundle));
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  assert(c.root_dirfd >= 0);
  char current[128] = {0};
  assert(readlinkat(c.root_dirfd, "current", current, sizeof current - 1) > 0);
  /* Use the actual bootstrap result, so the pre-fix synthetic ID reaches
   * health. */
  d2ku_journal j = {
      .schema = 1, .sequence = 1, .phase = D2KU_STOPPING, .active_services = 4};
  strcpy(j.transaction_id, "first-update");
  j.transaction_id_len = strlen(j.transaction_id);
  strcpy(j.old_release_id, current + 9);
  j.old_release_id_len = strlen(j.old_release_id);
  strcpy(j.new_release_id, "failed-candidate");
  j.new_release_id_len = strlen(j.new_release_id);
  strcpy(j.progress_boot_id, "previous-boot");
  j.progress_boot_id_len = strlen(j.progress_boot_id);
  snprintf(path, sizeof path, "%s/%s/.d2ku-receipt", root, current);
  FILE *f = fopen(path, "r");
  assert(f);
  char seal[65];
  assert(fscanf(f, "D2KR1 13 1 1 %64s", seal) == 1);
  fclose(f);
  for (unsigned i = 0; i < 32; i++) {
    unsigned byte;
    assert(sscanf(seal + 2 * i, "%2x", &byte) == 1);
    j.old_manifest_sha256[i] = (unsigned char)byte;
  }
  memset(j.new_manifest_sha256, 7, 32);
  d2ku_persistent_state policy = {.schema = 1, .sequence = 1, .trust_count = 1};
  policy.trust[0].not_after = 1792000000;
  assert(d2ku_persistent_store(&c, &policy) == D2KU_OK);
  assert(d2ku_journal_store(&c, &j) == D2KU_OK);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    execl(argv[2], argv[2], "--root", root, "service", "heal", (char *)NULL);
    _exit(127);
  }
  int status = 0;
  for (;;) {
    pid_t gone = waitpid(-1, &status, 0);
    assert(gone > 0);
    if (gone == child)
      break;
  }
  int result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  fprintf(stderr, "external recovery exit=%d\n", result);
  snprintf(path, sizeof path, "%s/panel.pid", root);
  f = fopen(path, "r");
  if (f) {
    long pid;
    if (fscanf(f, "%ld", &pid) == 1)
      kill((pid_t)pid, SIGTERM);
    fclose(f);
  }
  usleep(100000);
  reap();
  assert(result == 0);
  assert(!strcmp(current, "releases/flat-original"));
  assert(d2ku_journal_load(&c, &j) == D2KU_OK && j.phase == D2KU_ROLLED_BACK);
  assert(d2ku_persistent_load(&c, &policy) == D2KU_OK &&
         policy.policy.has_quarantined_release);
  assert(faccessat(c.root_dirfd, "external-finished", F_OK, 0) == 0);
  close(c.root_dirfd);
  snprintf(cmd, sizeof cmd, "rm -rf %s", temp);
  assert(!system(cmd));
  puts("bootstrap -> interrupted first update -> external recovery: original "
       "identity, proc inode, health fd and full observation PASS");
}
