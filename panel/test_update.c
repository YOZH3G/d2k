#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "../update/include/d2k_update_ipc.h"
#include "server.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
static const char *socket_path = "/nonexistent/d2k-update.sock";
static int listener, reply_code;
static void *backend(void *arg) {
  (void)arg;
  int client = accept(listener, NULL, NULL);
  assert(client >= 0);
  d2ku_command c;
  assert(!d2ku_ipc_receive(client, &c));
  assert(c.op == D2KU_CMD_INSTALL && !strcmp(c.release_id, "selected") &&
         c.hash[0] == 0x42 && !strcmp(c.operation_id, "panel-operation"));
  assert(!d2ku_ipc_reply(client, reply_code,
                         "{\"operation_id\":\"same-operation\"}"));
  close(client);
  return NULL;
}
static void request(const char *method, const char *path, const char *origin,
                    const char *body, int enabled, int code) {
  int s[2];
  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, s));
  int sendbuf = 65536;
  assert(!setsockopt(s[0], SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof sendbuf));
  char b[32768];
  int n = snprintf(
      b, sizeof b,
      "%s %s HTTP/1.1\r\nHost: local\r\n%sContent-Length: %zu\r\n\r\n%s",
      method, path, origin, strlen(body), body);
  assert(write(s[0], b, (size_t)n) == n);
  shutdown(s[0], SHUT_WR);
  d2k_panel_config c = {.control_enabled = enabled,
                        .update_socket = socket_path};
  assert(!d2k_panel_handle_fd(s[1], &c));
  close(s[1]);
  n = (int)read(s[0], b, sizeof b - 1);
  assert(n > 0);
  b[n] = 0;
  char expected[32];
  snprintf(expected, sizeof expected, "HTTP/1.1 %d", code);
  assert(strstr(b, expected));
  if (code == 503)
    assert(strstr(b, "unavailable"));
  close(s[0]);
}
int main(void) {
  request("GET", "/api/update", "", "", 1, 503);
  request("GET", "/api/update/check", "", "", 1, 405);
  request("POST", "/api/update/check", "", "{}", 1, 403);
  request("POST", "/api/update/check", "Origin: http://evil\r\n", "{}", 1, 403);
  request("POST", "/api/update/check", "Origin: http://local\r\n", "{}", 0,
          403);
  request("POST", "/api/update/check", "Origin: http://local\r\n",
          "{\"force\":true}", 1, 503);
  request("POST", "/api/update/install", "Origin: http://local\r\n", "{}", 1,
          400);
  request("POST", "/api/update/check", "Origin: http://local\r\n",
          "{\"url\":\"evil\"}", 1, 400);
  char huge[17000];
  memset(huge, ' ', sizeof huge - 1);
  huge[sizeof huge - 1] = 0;
  request("POST", "/api/update/check", "Origin: http://local\r\n", huge, 1,
          413);
  char root[] = "/tmp/d2ku-panel-XXXXXX";
  assert(mkdtemp(root));
  char path[104];
  snprintf(path, sizeof path, "%s/socket", root);
  socket_path = path;
  listener = socket(AF_UNIX, SOCK_STREAM, 0);
  assert(listener >= 0);
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  strcpy(a.sun_path, path);
  assert(!bind(listener, (struct sockaddr *)&a, sizeof a));
  assert(!chmod(path, 0600));
  assert(!listen(listener, 2));
  for (int i = 0; i < 2; i++) {
    pthread_t t;
    reply_code = i ? 409 : 202;
    assert(!pthread_create(&t, NULL, backend, NULL));
    request(
        "POST", "/api/update/install", "Origin: http://local\r\n",
        "{\"operation_id\":\"panel-operation\",\"release_id\":\"selected\","
        "\"manifest_sha256\":"
        "\"4200000000000000000000000000000000000000000000000000000000000000\"}",
        1, reply_code);
    pthread_join(t, NULL);
  }
  close(listener);
  unlink(path);
  rmdir(root);
  puts("panel update: methods, origin, control, body, unavailable: PASS");
}
