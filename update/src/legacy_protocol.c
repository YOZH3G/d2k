#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "../../runtime/d2k_runtime.h"
#include "legacy.h"
#include "transaction_internal.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
/* A private, event-free AF_UNIX peer proves the preserved controller accepts
 * exactly the historical protocol. Every writable path is private scratch;
 * no competing connection to the live datapath and no network probe occurs. */
static d2ku_rc greeting(d2ku_ctx *c, int saved, const char *scratch,
                        unsigned wire) {
  char sock[108], catalog[160], live[160], log[160], cache[160];
  snprintf(sock, sizeof sock, "%s/control", scratch);
  snprintf(catalog, sizeof catalog, "%s/catalog", scratch);
  snprintf(live, sizeof live, "%s/live", scratch);
  snprintf(log, sizeof log, "%s/log", scratch);
  snprintf(cache, sizeof cache, "%s/https", scratch);
  int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener < 0)
    return D2KU_IO;
  fcntl(listener, F_SETFD, FD_CLOEXEC);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, sock);
  if (bind(listener, (void *)&address, sizeof address) || listen(listener, 1)) {
    close(listener);
    return D2KU_IO;
  }
  int gate[2];
  if (pipe(gate)) {
    close(listener);
    unlink(sock);
    return D2KU_IO;
  }
  pid_t child = fork();
  if (child < 0) {
    close(gate[0]);
    close(gate[1]);
    close(listener);
    unlink(sock);
    return D2KU_IO;
  }
  if (!child) {
    close(gate[1]);
    char go;
    if (read(gate[0], &go, 1) != 1 || go != 'G')
      _exit(126);
    close(gate[0]);
    close(listener);
    if (setpgid(0, 0) || fchdir(saved))
      _exit(126);
    int null = open("/dev/null", O_RDWR);
    if (null < 0 || dup2(null, 1) < 0 || dup2(null, 2) < 0)
      _exit(126);
    if (null > 2)
      close(null);
    close(3);
    close(4);
    close(5);
    execl("./d2kc", "d2kc", "--control", sock, "--catalog", catalog, "--live",
          live, "--log", log, "--https-cache", cache, (char *)NULL);
    _exit(127);
  }
  close(gate[0]);
  d2ku_rc rc = d2ku_boot_group(c, child, 1);
  if (rc == D2KU_OK && write(gate[1], "G", 1) != 1)
    rc = D2KU_IO;
  close(gate[1]);
  int peer = -1, exited = 0, status = 0, got = 0;
  uint64_t begin = d2k_runtime_mono_ms();
  while (rc == D2KU_OK && d2k_runtime_mono_ms() - begin < 4000) {
    struct pollfd p = {peer < 0 ? listener : peer, POLLIN, 0};
    int ready = poll(&p, 1, 20);
    if (ready > 0 && peer < 0) {
      peer = accept(listener, NULL, NULL);
      if (peer < 0) {
        rc = D2KU_IO;
        break;
      }
      unsigned char frame[50] = {0};
      frame[3] = 46;
      frame[5] = 10;
      frame[6] = 4;
      frame[45] = (unsigned char)wire;
      frame[48] = 6;
      frame[49] = 64;
      if (write(peer, frame, sizeof frame) != (ssize_t)sizeof frame) {
        rc = D2KU_IO;
        break;
      }
    } else if (ready > 0 && peer >= 0) {
      unsigned char response[6];
      ssize_t n = recv(peer, response, sizeof response, MSG_DONTWAIT);
      if (n > 0) {
        got = 1;
        break;
      }
    }
    if (waitpid(child, &status, WNOHANG) == child) {
      exited = 1;
      break;
    }
    if (wire == 12) {
      int lf = open(live, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      if (lf >= 0) {
        char b[80] = {0};
        ssize_t bytes = read(lf, b, sizeof b - 1);
        close(lf);
        if (bytes > 0 && strstr(b, "\"linked\": true")) {
          got = 1;
          break;
        }
      }
    }
    struct stat st;
    if (!stat(log, &st) && st.st_size > 16384) {
      rc = D2KU_INCOMPATIBLE;
      break;
    }
  }
  int accepted = wire == 12 ? got && !exited
                            : !got && exited && WIFEXITED(status) &&
                                  WEXITSTATUS(status) == 1;
  if (!exited) {
    kill(child, SIGTERM);
    uint64_t end = d2k_runtime_mono_ms() + 1000;
    while (d2k_runtime_mono_ms() < end) {
      if (waitpid(child, &status, WNOHANG) == child) {
        exited = 1;
        break;
      }
      struct timespec t = {0, 10000000};
      nanosleep(&t, NULL);
    }
  }
  if (!exited) {
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
  }
  d2ku_rc cleaned = d2ku_group_cleanup(child);
  if (cleaned == D2KU_OK)
    cleaned = d2ku_boot_group(c, child, 0);
  if (peer >= 0)
    close(peer);
  close(listener);
  unlink(sock);
  if (rc != D2KU_OK)
    return rc;
  if (cleaned != D2KU_OK)
    return cleaned;
  return accepted ? D2KU_OK : D2KU_INCOMPATIBLE;
}
d2ku_rc d2ku_legacy_protocol(d2ku_ctx *c, int saved) {
  char scratch[] = "/tmp/d2ku-legacy-protocol.XXXXXX";
  if (!mkdtemp(scratch))
    return D2KU_IO;
  d2ku_rc rc = greeting(c, saved, scratch, 13);
  if (rc == D2KU_OK)
    rc = greeting(c, saved, scratch, 12);
  /* Only known scratch outputs can be removed. Unknown output is incompatible.
   */
  const char *names[] = {"control",
                         "catalog",
                         "catalog.new",
                         "live",
                         "live.new",
                         "log",
                         "https",
                         "https.new",
                         "http-plans.txt",
                         "http-plans.txt.new",
                         "http-plans.json",
                         "http-plans.json.new",
                         "https-cache.json",
                         "https-cache.json.new"};
  int d = open(scratch, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (d >= 0) {
    for (unsigned i = 0; i < sizeof names / sizeof *names; i++)
      unlinkat(d, names[i], 0);
    close(d);
  }
  if (rmdir(scratch))
    rc = D2KU_INCOMPATIBLE;
  return rc;
}
