#define _POSIX_C_SOURCE 200809L
#include "update.h"
#include "../update/include/d2k_update_ipc.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
static int send_all(int fd, const char *p, size_t n) {
  while (n) {
    ssize_t k = write(fd, p, n);
    if (k < 0 && errno == EINTR)
      continue;
    if (k <= 0)
      return -1;
    p += k;
    n -= (size_t)k;
  }
  return 0;
}
static int reply(int fd, int code, const char *body) {
  const char *reason = code == 200   ? "OK"
                       : code == 202 ? "Accepted"
                       : code == 400 ? "Bad Request"
                       : code == 403 ? "Forbidden"
                       : code == 404 ? "Not Found"
                       : code == 405 ? "Method Not Allowed"
                       : code == 409 ? "Conflict"
                       : code == 413 ? "Content Too Large"
                                     : "Service Unavailable";
  char h[256];
  int n = snprintf(h, sizeof h,
                   "HTTP/1.1 %d %s\r\nContent-Type: application/json; "
                   "charset=utf-8\r\nCache-Control: no-store\r\nConnection: "
                   "close\r\nContent-Length: %zu\r\n\r\n",
                   code, reason, strlen(body));
  return send_all(fd, h, (size_t)n) || send_all(fd, body, strlen(body)) ? -1
                                                                        : 0;
}
static int body_read(int fd, const char *request, char *body) {
  const char *end = strstr(request, "\r\n\r\n");
  if (!end)
    return 400;
  const char *p = strstr(request, "\r\n") + 2;
  size_t len = 0;
  int seen = 0;
  while (p < end) {
    const char *e = strstr(p, "\r\n"), *colon = memchr(p, ':', (size_t)(e - p));
    if (!colon)
      return 400;
    size_t n = (size_t)(colon - p);
    const char *v = colon + 1;
    while (v < e && (*v == ' ' || *v == '\t'))
      v++;
    if (n == 17 && !strncasecmp(p, "Transfer-Encoding", n))
      return 400;
    if (n == 14 && !strncasecmp(p, "Content-Length", n)) {
      if (seen++ || v == e)
        return 400;
      while (v < e && *v >= '0' && *v <= '9') {
        if (len > D2KU_JSON_MAX)
          return 413;
        len = len * 10 + (unsigned)(*v++ - '0');
      }
      while (v < e && (*v == ' ' || *v == '\t'))
        v++;
      if (v != e)
        return 400;
    }
    p = e + 2;
  }
  if (len > D2KU_JSON_MAX)
    return 413;
  p = end + 4;
  size_t have = strlen(p);
  if (have > len)
    return 400;
  memcpy(body, p, have);
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  time_t deadline = t.tv_sec + 2;
  while (have < len) {
    clock_gettime(CLOCK_MONOTONIC, &t);
    if (t.tv_sec >= deadline)
      return 400;
    struct pollfd f = {fd, POLLIN, 0};
    int r = poll(&f, 1, 100);
    if (r < 0 && errno == EINTR)
      continue;
    if (r < 0)
      return 400;
    if (!r)
      continue;
    ssize_t n = read(fd, body + have, len - have);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return 400;
    have += (size_t)n;
  }
  if (memchr(body, 0, len))
    return 400;
  body[len] = 0;
  if (!len)
    strcpy(body, "{}");
  return 0;
}
int d2k_panel_update_handle(int fd, const d2k_panel_config *cfg,
                            const char *req, const char *path) {
  char method[8];
  if (sscanf(req, "%7s", method) != 1)
    return reply(fd, 400, "{\"error\":\"request\"}");
  d2ku_command_op op;
  if (!strcmp(path, "/api/update"))
    op = D2KU_CMD_STATUS;
  else if (!strcmp(path, "/api/update/check"))
    op = D2KU_CMD_CHECK;
  else if (!strcmp(path, "/api/update/install"))
    op = D2KU_CMD_INSTALL;
  else if (!strcmp(path, "/api/update/rollback"))
    op = D2KU_CMD_ROLLBACK;
  else if (!strcmp(path, "/api/update/settings"))
    op = D2KU_CMD_SETTINGS;
  else
    return reply(fd, 404, "{\"error\":\"path\"}");
  if (strcmp(method, op == D2KU_CMD_STATUS ? "GET" : "POST"))
    return reply(fd, 405, "{\"error\":\"method\"}");
  if (op != D2KU_CMD_STATUS &&
      (!cfg || !cfg->control_enabled || !d2k_panel_same_origin(req)))
    return reply(fd, 403, "{\"error\":\"control_forbidden\"}");
  char body[D2KU_JSON_MAX + 1];
  int error = body_read(fd, req, body);
  if (error)
    return reply(fd, error, "{\"error\":\"body\"}");
  d2ku_command command;
  if (d2ku_command_parse(op, body, &command))
    return reply(fd, 400, "{\"error\":\"command\"}");
  int ipc = d2ku_ipc_connect(cfg && cfg->update_socket ? cfg->update_socket
                                                       : D2KU_SOCKET);
  if (ipc < 0)
    return reply(fd, 503, "{\"state\":\"unavailable\"}");
  char *out = malloc(D2KU_IPC_MAX + 1);
  int code = 503;
  int r =
      out ? d2ku_ipc_exchange(ipc, &command, &code, out, D2KU_IPC_MAX + 1) : -1;
  close(ipc);
  if (r || !(code == 200 || code == 202 || code == 400 || code == 409 ||
             code == 503)) {
    free(out);
    return reply(fd, 503, "{\"state\":\"unavailable\"}");
  }
  r = reply(fd, code, out);
  free(out);
  return r;
}
