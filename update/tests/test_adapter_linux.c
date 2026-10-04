/* Isolated Linux container only. Arguments: ADAPTER S99 UNINSTALL.
 * Private runtime and command doubles; full uninstall removes container-owned
 * /tmp/d2k leftovers, so never run this harness on an active router/host. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include "d2k_update.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
static void writefile(const char *path, const char *s) {
  FILE *f = fopen(path, "w");
  assert(f);
  assert(fputs(s, f) >= 0);
  assert(!fclose(f));
  assert(!chmod(path, 0600));
}
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "serve")) {
    const char *out = getenv("OBSERVED");
    assert(out);
    for (int i = 3; i <= 5; i++)
      assert(fcntl(i, F_GETFD) < 0 && errno == EBADF);
    FILE *f = fopen(out, "w");
    assert(f);
    fprintf(f, "%ld\n", (long)getpid());
    fclose(f);
    for (;;)
      pause();
  }
  assert(argc == 4);
#ifdef __linux__
  assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
#endif
  char root[] = "/tmp/d2ku-adapter-linux.XXXXXX";
  assert(mkdtemp(root));
  char p[1024], cmd[4096];
  snprintf(cmd, sizeof cmd,
           "mkdir -p -m 700 %s/boot %s/releases/old %s/update-state", root,
           root, root);
  assert(!system(cmd));
  snprintf(cmd, sizeof cmd, "cp %s %s/boot/d2k-service-adapter", argv[1], root);
  assert(!system(cmd));
  snprintf(cmd, sizeof cmd, "cp %s %s/releases/old/S99d2k", argv[2], root);
  assert(!system(cmd));
  snprintf(cmd, sizeof cmd, "cp %s %s/releases/old/d2kpanel", argv[0], root);
  assert(!system(cmd));
  snprintf(p, sizeof p, "%s/current", root);
  assert(!symlink("releases/old", p));
  snprintf(p, sizeof p, "%s/commands", root);
  assert(!mkdir(p, 0700));
  const char *tools[] = {"iptables", "ip6tables"};
  for (unsigned i = 0; i < 2; i++) {
    snprintf(p, sizeof p, "%s/commands/%s", root, tools[i]);
    writefile(p, "#!/bin/sh\ncase \"$*\" in *-S*) exit 0;; esac\nexit 1\n");
    assert(!chmod(p, 0700));
  }
  snprintf(p, sizeof p, "%s/config", root);
  char config[2048];
  snprintf(config, sizeof config,
           "STATE_DIR=%s/state\nD2K_RUNTIME_DIR=%s/"
           "runtime\nMODE=off\nTG_ENABLED=0\nPATH=%s/commands:/usr/sbin:/usr/"
           "bin:/sbin:/bin\nFW_LOCK=%s/fw.lock\n",
           root, root, root, root);
  writefile(p, config);
  d2ku_ctx c = {0};
  c.root_dirfd = open(root, O_RDONLY | O_DIRECTORY);
  int lock;
  assert(d2ku_maintenance_lock(&c, &lock) == D2KU_OK);
  snprintf(p, sizeof p, "%s/observed", root);
  setenv("OBSERVED", p, 1);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    assert(dup2(lock, 4) == 4);
    fcntl(4, F_SETFD, 0);
    execl(argv[1], argv[1], "--root", root, "--maintenance-fd", "4", "start",
          "old", "4", (char *)NULL);
    _exit(127);
  }
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  FILE *f = NULL;
  for (int i = 0; i < 100 && !f; i++) {
    struct stat ready;
    if (!stat(p, &ready) && ready.st_size > 0)
      f = fopen(p, "r");
    if (!f)
      usleep(20000);
  }
  assert(f);
  long daemon;
  assert(fscanf(f, "%ld", &daemon) == 1);
  fclose(f);
  close(lock);
  assert(d2ku_maintenance_lock(&c, &lock) == D2KU_OK);
  close(lock);
  pid_t recovery = fork();
  assert(recovery >= 0);
  if (!recovery) {
    for (;;)
      pause();
  }
  snprintf(p, sizeof p, "%s/run/d2k-update-boot.pid", root);
  char pidtext[40];
  snprintf(pidtext, sizeof pidtext, "%ld\n", (long)recovery);
  writefile(p, pidtext);
  child = fork();
  assert(child >= 0);
  if (!child) {
    execl(argv[1], argv[1], "--root", root, "service", "stop", (char *)NULL);
    _exit(127);
  }
  int daemon_reaped = 0;
  for (;;) {
    pid_t gone = waitpid(-1, &status, 0);
    assert(gone > 0);
    assert(gone != recovery);
    if (gone == (pid_t)daemon)
      daemon_reaped = 1;
    if (gone == child)
      break;
  }
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  assert(daemon_reaped);
  assert(!kill(recovery, 0));
  kill(recovery, SIGTERM);
  assert(waitpid(recovery, &status, 0) == recovery);
  snprintf(p, sizeof p, "%s/state/catalog.json", root);
  writefile(p, "learned fixture\n");
  snprintf(p, sizeof p, "%s/state/tg.identity", root);
  writefile(p, "personal fixture\n");
  snprintf(cmd, sizeof cmd,
           "cp %s %s/boot/uninstall.sh && chmod 700 %s/boot/uninstall.sh",
           argv[3], root, root);
  assert(!system(cmd));
  char files[1024];
  snprintf(files, sizeof files, "%s", argv[2]);
  char *slash = strrchr(files, '/');
  assert(slash);
  *slash = 0;
  snprintf(
      cmd, sizeof cmd,
      "cp %s/d2k-instagram-dns.sh %s/d2k-instagram-dns.sh && cp "
      "%s/d2k-instagram-dns.sh %s/releases/old/d2k-instagram-dns.sh && chmod "
      "700 %s/d2k-instagram-dns.sh %s/releases/old/d2k-instagram-dns.sh",
      files, root, files, root, root, root);
  assert(!system(cmd));
  setenv("D2K_KEEP_STATE", "1", 1);
  child = fork();
  assert(child >= 0);
  if (!child) {
    execl(argv[1], argv[1], "--root", root, "service", "uninstall",
          (char *)NULL);
    _exit(127);
  }
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  snprintf(p, sizeof p, "%s/state/catalog.json", root);
  f = fopen(p, "r");
  assert(f);
  char saved[64];
  assert(fgets(saved, sizeof saved, f) && !strcmp(saved, "learned fixture\n"));
  fclose(f);
  snprintf(p, sizeof p, "%s/state/tg.identity", root);
  assert(!access(p, R_OK));
  snprintf(p, sizeof p, "%s/config", root);
  assert(!access(p, R_OK));
  snprintf(p, sizeof p, "%s/boot", root);
  assert(access(p, F_OK) < 0 && errno == ENOENT);
  assert(d2ku_maintenance_lock(&c, &lock) == D2KU_OK);
  close(lock);
  close(c.root_dirfd);
  snprintf(cmd, sizeof cmd, "rm -rf %s", root);
  assert(!system(cmd));
  puts("Linux actual adapter, FD closure, writer reaping and independent "
       "recovery survives stop: "
       "PASS");
  return 0;
}
