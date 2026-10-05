#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#define _GNU_SOURCE
#include "d2k_update_ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* A small strict object grammar: only the documented scalar keys are accepted.
 * No string escaping is needed for ASCII release IDs/hashes. Duplicate/unknown
 * keys, trailing input and all nested values fail before contacting the daemon.
 */
static void ws(const char **p) {
  while (**p && strchr(" \t\r\n", **p))
    ++*p;
}
static int string(const char **p, char *out, size_t cap) {
  ws(p);
  if (*(*p)++ != '"')
    return -1;
  size_t n = 0;
  while (**p && **p != '"') {
    unsigned char c = (unsigned char)*(*p)++;
    if (c < 0x20 || c > 0x7e || c == '\\' || n + 1 >= cap)
      return -1;
    out[n++] = (char)c;
  }
  if (**p != '"')
    return -1;
  ++*p;
  out[n] = 0;
  return 0;
}
static int boolean(const char **p, int *v) {
  ws(p);
  if (!strncmp(*p, "true", 4)) {
    *p += 4;
    *v = 1;
    return 0;
  }
  if (!strncmp(*p, "false", 5)) {
    *p += 5;
    *v = 0;
    return 0;
  }
  return -1;
}
static int hex(char c) {
  return c >= '0' && c <= '9'   ? c - '0'
         : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                : -1;
}
static int id_valid(const char *p) {
  if (!*p || *p == '.')
    return 0;
  for (; *p; p++)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || strchr("._-", *p)))
      return 0;
  return 1;
}
int d2ku_command_parse(d2ku_command_op op, const char *json,
                       d2ku_command *out) {
  if (!json || !out || strlen(json) > D2KU_JSON_MAX || op < D2KU_CMD_STATUS ||
      op > D2KU_CMD_QUIESCE)
    return -1;
  d2ku_command c = {.op = op};
  unsigned seen = 0;
  const char *p = json;
  ws(&p);
  if (*p++ != '{')
    return -1;
  ws(&p);
  while (*p != '}') {
    char key[32], val[65];
    unsigned bit;
    if (string(&p, key, sizeof key))
      return -1;
    ws(&p);
    if (*p++ != ':')
      return -1;
    if (!strcmp(key, "force") && op == D2KU_CMD_CHECK) {
      bit = 1;
      if (boolean(&p, &c.force))
        return -1;
    } else if (!strcmp(key, "enabled") && op == D2KU_CMD_SETTINGS) {
      bit = 2;
      if (boolean(&p, &c.enabled))
        return -1;
    } else if (!strcmp(key, "release_id") &&
               (op == D2KU_CMD_INSTALL || op == D2KU_CMD_ROLLBACK)) {
      bit = 4;
      if (string(&p, c.release_id, sizeof c.release_id) ||
          !id_valid(c.release_id))
        return -1;
    } else if (!strcmp(key, "manifest_sha256") &&
               (op == D2KU_CMD_INSTALL || op == D2KU_CMD_ROLLBACK)) {
      bit = 8;
      if (string(&p, val, sizeof val) || strlen(val) != 64)
        return -1;
      for (size_t i = 0; i < 32; i++) {
        int a = hex(val[i * 2]), b = hex(val[i * 2 + 1]);
        if (a < 0 || b < 0)
          return -1;
        c.hash[i] = (unsigned char)(a * 16 + b);
      }
    } else if (!strcmp(key, "operation_id") && op != D2KU_CMD_STATUS &&
               op != D2KU_CMD_QUIESCE) {
      bit = 16;
      if (string(&p, c.operation_id, sizeof c.operation_id) ||
          !id_valid(c.operation_id))
        return -1;
    } else
      return -1;
    if (seen & bit)
      return -1;
    seen |= bit;
    ws(&p);
    if (*p == '}')
      break;
    if (*p++ != ',')
      return -1;
    ws(&p);
    if (*p == '}')
      return -1;
  }
  if (*p++ != '}')
    return -1;
  ws(&p);
  if (*p)
    return -1;
  if (op == D2KU_CMD_SETTINGS && (seen & ~16u) != 2)
    return -1;
  if ((op == D2KU_CMD_INSTALL || op == D2KU_CMD_ROLLBACK) &&
      (seen & ~16u) != 12)
    return -1;
  *out = c;
  return 0;
}
static uint64_t now(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return 0;
  return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int io(int fd, void *buf, size_t len, int writing, uint64_t end) {
  unsigned char *p = buf;
  while (len) {
    uint64_t t = now();
    if (t >= end)
      return -1;
    struct pollfd f = {fd, writing ? POLLOUT : POLLIN, 0};
    int r = poll(&f, 1, (int)(end - t));
    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return -1;
    ssize_t n;
    if (writing) {
#ifdef MSG_NOSIGNAL
      n = send(fd, p, len, MSG_NOSIGNAL | MSG_DONTWAIT);
#else
      n = send(fd, p, len, MSG_DONTWAIT);
#endif
    } else
      n = recv(fd, p, len, MSG_DONTWAIT);
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (n <= 0)
      return -1;
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 0;
}
static void put32(unsigned char *p, uint32_t n) {
  for (unsigned i = 0; i < 4; i++)
    p[3 - i] = (unsigned char)(n >> (i * 8));
}
static uint32_t get32(const unsigned char *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static int frame(int fd, void *data, size_t *len, int writing, uint64_t end) {
  unsigned char h[12];
  if (writing) {
    memcpy(h, "D2UI", 4);
    put32(h + 4, 1);
    put32(h + 8, (uint32_t)*len);
  }
  if (io(fd, h, sizeof h, writing, end))
    return -1;
  if (!writing) {
    uint32_t n = get32(h + 8);
    if (memcmp(h, "D2UI", 4) || get32(h + 4) != 1 || !n || n > *len ||
        n > D2KU_IPC_MAX)
      return -1;
    *len = n;
  }
  return io(fd, data, *len, writing, end);
}
int d2ku_ipc_peer(int fd, uid_t expected) {
#ifdef __linux__
  struct ucred c;
  socklen_t n = sizeof c;
  return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &c, &n) || c.uid != expected
             ? -1
             : 0;
#else
  uid_t u;
  gid_t g;
  return getpeereid(fd, &u, &g) || u != expected ? -1 : 0;
#endif
}
int d2ku_ipc_connect(const char *path) {
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  struct stat st;
  if (!path || strlen(path) >= sizeof a.sun_path || lstat(path, &st) ||
      !S_ISSOCK(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077))
    return -1;
  strcpy(a.sun_path, path);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  fcntl(fd, F_SETFD, FD_CLOEXEC);
  fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
  if (connect(fd, (struct sockaddr *)&a, sizeof a) ||
      d2ku_ipc_peer(fd, geteuid())) {
    close(fd);
    return -1;
  }
  return fd;
}
/* Fixed 166-byte request: op/force/enabled/reserved + NUL-padded release ID +
 * hash + operation ID. This is explicit byte encoding, never a serialized C
 * structure or pointer. */
int d2ku_ipc_receive_lock(int fd, d2ku_command *c, int *lock_fd) {
  unsigned char b[166], h[12];
  union {
    struct cmsghdr align;
    unsigned char bytes[CMSG_SPACE(sizeof(int) * 8)];
  } control;
  memset(&control, 0, sizeof control);
  struct iovec v = {h, 1};
  struct msghdr msg = {0};
  msg.msg_iov = &v;
  msg.msg_iovlen = 1;
  msg.msg_control = control.bytes;
  msg.msg_controllen = sizeof control.bytes;
  struct pollfd f = {fd, POLLIN, 0};
  if (poll(&f, 1, 1000) <= 0)
    return -1;
  ssize_t got = recvmsg(fd, &msg, 0);
  int received = -1,
      bad = got != 1 || !!(msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC));
  size_t count = 0;
  for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msg); ch;
       ch = CMSG_NXTHDR(&msg, ch)) {
    if (ch->cmsg_level != SOL_SOCKET || ch->cmsg_type != SCM_RIGHTS ||
        ch->cmsg_len < CMSG_LEN(0)) {
      bad = 1;
      continue;
    }
    size_t n = (ch->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    int *fds = (int *)CMSG_DATA(ch);
    for (size_t i = 0; i < n; i++) {
      count++;
      if (received < 0)
        received = fds[i];
      else
        close(fds[i]);
    }
  }
  if (count > 1)
    bad = 1;
  uint64_t end = now() + 1000;
  if (!bad &&
      (io(fd, h + 1, 11, 0, end) || memcmp(h, "D2UI", 4) || get32(h + 4) != 1 ||
       get32(h + 8) != sizeof b || io(fd, b, sizeof b, 0, end)))
    bad = 1;
  if (!bad && (b[0] < 1 || b[0] > 6 || b[1] > 1 || b[2] > 1 || b[3] ||
               (!memchr(b + 4, 0, 65) || !memchr(b + 101, 0, 65))))
    bad = 1;
  if (!bad && ((b[0] == D2KU_CMD_QUIESCE) != (count == 1)))
    bad = 1;
  if (bad) {
    if (received >= 0)
      close(received);
    return -1;
  }
  memset(c, 0, sizeof *c);
  c->op = (d2ku_command_op)b[0];
  c->force = b[1];
  c->enabled = b[2];
  memcpy(c->release_id, b + 4, 65);
  memcpy(c->hash, b + 69, 32);
  memcpy(c->operation_id, b + 101, 65);
  if (c->operation_id[0] && !id_valid(c->operation_id))
    goto invalid;
  for (size_t k = strlen(c->operation_id); k < 65; k++)
    if (b[101 + k])
      goto invalid;
  size_t l = strlen(c->release_id);
  for (size_t i = l; i < 65; i++)
    if (b[4 + i])
      goto invalid;
  if ((c->op == D2KU_CMD_INSTALL || c->op == D2KU_CMD_ROLLBACK) &&
      !id_valid(c->release_id))
    goto invalid;
  if (c->force && c->op != D2KU_CMD_CHECK)
    goto invalid;
  if (c->enabled && c->op != D2KU_CMD_SETTINGS)
    goto invalid;
  if (received >= 0 && fcntl(received, F_SETFD, FD_CLOEXEC))
    goto invalid;
  *lock_fd = received;
  return 0;
invalid:
  if (received >= 0)
    close(received);
  return -1;
}
int d2ku_ipc_receive(int fd, d2ku_command *c) {
  int lock = -1;
  int r = d2ku_ipc_receive_lock(fd, c, &lock);
  if (lock >= 0) {
    close(lock);
    return -1;
  }
  return r;
}
int d2ku_ipc_reply(int fd, int code, const char *json) {
  size_t n = strlen(json);
  if (n > D2KU_IPC_MAX - 4)
    return -1;
  unsigned char h[12], c[4];
  memcpy(h, "D2UI", 4);
  put32(h + 4, 1);
  put32(h + 8, (uint32_t)n + 4);
  put32(c, (uint32_t)code);
  uint64_t end = now() + 1000;
  return io(fd, h, 12, 1, end) || io(fd, c, 4, 1, end) ||
                 io(fd, (void *)json, n, 1, end)
             ? -1
             : 0;
}
int d2ku_ipc_exchange_lock(int fd, const d2ku_command *c, int lock_fd,
                           int *code, char *out, size_t cap) {
  if (!c || !code || !out || cap < 5 ||
      (strnlen(c->release_id, 65) == 65 || strnlen(c->operation_id, 65) == 65))
    return -1;
  unsigned char b[166] = {0};
  b[0] = (unsigned char)c->op;
  b[1] = (unsigned char)c->force;
  b[2] = (unsigned char)c->enabled;
  memcpy(b + 4, c->release_id, strlen(c->release_id));
  memcpy(b + 69, c->hash, 32);
  memcpy(b + 101, c->operation_id, strlen(c->operation_id));
  size_t n = sizeof b;
  uint64_t end = now() + 1000;
  if (lock_fd >= 0) {
    if (c->op != D2KU_CMD_QUIESCE)
      return -1;
    unsigned char h[12];
    memcpy(h, "D2UI", 4);
    put32(h + 4, 1);
    put32(h + 8, (uint32_t)n);
    union {
      struct cmsghdr align;
      unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof control);
    struct iovec v = {h, 1};
    struct msghdr msg = {0};
    msg.msg_iov = &v;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof control.bytes;
    struct cmsghdr *ch = CMSG_FIRSTHDR(&msg);
    ch->cmsg_level = SOL_SOCKET;
    ch->cmsg_type = SCM_RIGHTS;
    ch->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(ch), &lock_fd, sizeof lock_fd);
#ifdef MSG_NOSIGNAL
    ssize_t sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
#else
    ssize_t sent = sendmsg(fd, &msg, 0);
#endif
    if (sent != 1 || io(fd, h + 1, 11, 1, end) || io(fd, b, n, 1, end))
      return -1;
  } else if (frame(fd, b, &n, 1, end))
    return -1;
  n = cap - 1;
  if (frame(fd, out, &n, 0, end) || n < 4)
    return -1;
  *code = (int)get32((unsigned char *)out);
  memmove(out, out + 4, n - 4);
  out[n - 4] = 0;
  return 0;
}

int d2ku_ipc_exchange(int fd, const d2ku_command *c, int *code, char *out,
                      size_t cap) {
  return d2ku_ipc_exchange_lock(fd, c, -1, code, out, cap);
}
