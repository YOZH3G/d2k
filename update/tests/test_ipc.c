#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _DEFAULT_SOURCE
#include "d2k_update_ipc.h"
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static void *server(void *p) {
  int fd = *(int *)p;
  d2ku_command cmd;
  assert(d2ku_ipc_receive(fd, &cmd) == 0);
  assert(cmd.op == D2KU_CMD_INSTALL);
  assert(!strcmp(cmd.release_id, "selected"));
  assert(cmd.hash[0] == 0x42);
  assert(d2ku_ipc_reply(fd, 202, "{\"operation_id\":\"one\"}") == 0);
  return NULL;
}
static void *receiver(void *p) {
  int fd = *(int *)p, lock = -1;
  d2ku_command c;
  assert(d2ku_ipc_receive_lock(fd, &c, &lock) == 0);
  assert(c.op == D2KU_CMD_QUIESCE && lock >= 0);
  assert(fcntl(lock, F_GETFD) & FD_CLOEXEC);
  close(lock);
  assert(d2ku_ipc_reply(fd, 202, "{}") == 0);
  return NULL;
}
static int open_fds(void) {
  int count = 0;
  for (int fd = 0; fd < 256; fd++)
    if (fcntl(fd, F_GETFD) >= 0)
      count++;
  return count;
}
static void malformed_rights(void) {
  int pair[2], descriptor = open("/dev/null", O_RDONLY);
  assert(descriptor >= 0 && !socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
  int before = open_fds();
  char control[CMSG_SPACE(sizeof(int) * 2)] = {0}, byte = 'D';
  struct iovec iov = {.iov_base = &byte, .iov_len = 1};
  struct msghdr message = {.msg_iov = &iov,
                           .msg_iovlen = 1,
                           .msg_control = control,
                           .msg_controllen = sizeof control};
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int) * 2);
  int rights[2] = {descriptor, descriptor};
  memcpy(CMSG_DATA(header), rights, sizeof rights);
  assert(sendmsg(pair[0], &message, 0) == 1);
  d2ku_command command;
  int received = -1;
  assert(d2ku_ipc_receive_lock(pair[1], &command, &received) < 0);
  assert(received == -1 && before == open_fds());
  close(descriptor);
  close(pair[0]);
  close(pair[1]);
}
int main(void) {
  malformed_rights();
  d2ku_command c;
  assert(d2ku_command_parse(D2KU_CMD_CHECK, "{\"force\":true}", &c) == 0 &&
         c.force);
  assert(d2ku_command_parse(D2KU_CMD_CHECK, "{\"force\":true,\"force\":false}",
                            &c) < 0);
  assert(d2ku_command_parse(D2KU_CMD_INSTALL, "{}", &c) < 0);
  assert(d2ku_command_parse(D2KU_CMD_CHECK, "{\"url\":\"https://attacker\"}",
                            &c) < 0);
  assert(d2ku_command_parse(D2KU_CMD_SETTINGS, "{\"enabled\":false}", &c) ==
             0 &&
         !c.enabled);
  int f[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
  assert(d2ku_ipc_peer(f[0], geteuid()) == 0);
  assert(d2ku_ipc_peer(f[0], geteuid() + 1) < 0);
  pthread_t t;
  assert(pthread_create(&t, NULL, server, &f[1]) == 0);
  memset(&c, 0, sizeof c);
  c.op = D2KU_CMD_INSTALL;
  strcpy(c.release_id, "selected");
  c.hash[0] = 0x42;
  int code;
  char body[256];
  assert(d2ku_ipc_exchange(f[0], &c, &code, body, sizeof body) == 0);
  assert(code == 202 && strstr(body, "one"));
  pthread_join(t, NULL);
  close(f[0]);
  close(f[1]);
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
  assert(write(f[0], "D2UI\0\0\0\1\377\377\377\377", 12) == 12);
  assert(d2ku_ipc_receive(f[1], &c) < 0);
  close(f[0]);
  close(f[1]);
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
  assert(!pthread_create(&t, NULL, receiver, &f[1]));
  int lock = open("/dev/null", O_RDONLY);
  assert(lock >= 0);
  memset(&c, 0, sizeof c);
  c.op = D2KU_CMD_QUIESCE;
  assert(!d2ku_ipc_exchange_lock(f[0], &c, lock, &code, body, sizeof body));
  close(lock);
  pthread_join(t, NULL);
  close(f[0]);
  close(f[1]);
  puts("ipc: strict requests, bounded v1 frames, authenticated peer: PASS");
}
