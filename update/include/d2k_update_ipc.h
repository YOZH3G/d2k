#ifndef D2K_UPDATE_IPC_H
#define D2K_UPDATE_IPC_H
#include <stddef.h>
#include <sys/types.h>
#define D2KU_IPC_MAX 131072u
#define D2KU_JSON_MAX 16384u
#define D2KU_SOCKET "/opt/d2k/update-state/updater.sock"
typedef enum {
  D2KU_CMD_STATUS = 1,
  D2KU_CMD_CHECK,
  D2KU_CMD_INSTALL,
  D2KU_CMD_ROLLBACK,
  D2KU_CMD_SETTINGS,
  D2KU_CMD_QUIESCE
} d2ku_command_op;
typedef struct {
  d2ku_command_op op;
  int force, enabled;
  char release_id[65], operation_id[65];
  unsigned char hash[32];
} d2ku_command;
int d2ku_command_parse(d2ku_command_op, const char *, d2ku_command *);
int d2ku_ipc_peer(int fd, uid_t expected);
int d2ku_ipc_connect(const char *path);
int d2ku_ipc_receive_lock(int fd, d2ku_command *, int *lock_fd);
int d2ku_ipc_exchange_lock(int fd, const d2ku_command *, int lock_fd, int *code,
                           char *, size_t);
int d2ku_ipc_receive(int fd, d2ku_command *);
int d2ku_ipc_reply(int fd, int code, const char *json);
int d2ku_ipc_exchange(int fd, const d2ku_command *, int *code, char *, size_t);
#endif
