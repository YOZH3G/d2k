/* Лабораторные границы для scripts/lab-update.sh. Только Linux, только внутри
 * закрытого контейнера лаборатории; в выпуск не входит и продуктом не
 * используется.
 *
 *   fault_matrix sync-exec CMD [ARGS...]
 *       Подмена ИСТОЧНИКА ВРЕМЕНИ, а не часов: seccomp-фильтр отвечает нулём
 *       на adjtimex/clock_adjtime, то есть «ядро считает часы
 *       синхронизированными». Docker-VM этого не сообщает, а менять её часы
 *       лаборатории запрещено. Стена, монотонные часы, boot_id и /etc/TZ
 *       остаются настоящими; окно здоровья 120 с идёт по настоящему
 *       CLOCK_MONOTONIC. Фильтр наследуют все потомки CMD.
 *
 *   fault_matrix trace-fault PID SYSCALL NTH error|kill -- (см. ниже)
 *       Не реализовано отдельным режимом: сбои durable-шагов настоящих
 *       процессов вводит strace --inject из драйвера лаборатории.
 *
 *   fault_matrix fill FILE
 *       Занять всё свободное место файловой системы FILE (настоящий ENOSPC
 *       на частном tmpfs /opt). Печатает число записанных байт.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int sync_exec(char **argv) {
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_adjtimex, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clock_adjtime, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0),
  };
  struct sock_fprog program = {sizeof filter / sizeof filter[0], filter};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) {
    perror("fault_matrix: seccomp");
    return 3;
  }
  execvp(argv[0], argv);
  perror("fault_matrix: exec");
  return 3;
}
#endif

static int fill(const char *path) {
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    perror("fault_matrix: fill");
    return 3;
  }
  static char block[65536];
  memset(block, 0x5a, sizeof block);
  unsigned long long total = 0;
  size_t want = sizeof block;
  while (want) {
    ssize_t n = write(fd, block, want);
    if (n > 0)
      total += (unsigned long long)n;
    else if (errno == ENOSPC || errno == EDQUOT)
      want /= 2; /* дожать остаток меньшими блоками */
    else if (errno != EINTR) {
      perror("fault_matrix: fill write");
      close(fd);
      return 3;
    }
  }
  close(fd);
  printf("%llu\n", total);
  return 0;
}

int main(int argc, char **argv) {
#ifdef __linux__
  if (argc >= 3 && !strcmp(argv[1], "sync-exec"))
    return sync_exec(argv + 2);
#endif
  if (argc == 3 && !strcmp(argv[1], "fill"))
    return fill(argv[2]);
  fprintf(stderr, "usage: fault_matrix sync-exec CMD [ARGS...] | fill FILE\n");
  return 2;
}
