/* test_mips_pipe.c — ловушка MIPS в обёртке pipe().
 *
 * Системный вызов pipe на MIPS возвращает ПЕРВЫЙ дескриптор в v0 (второй в
 * v1), и обёртка musl из zig отдаёт это значение как есть, вместо нуля POSIX.
 * Разбор 12.10.2026 (дизассемблер статического mips-linux-musleabi):
 *
 *     li $2, 4042      ; SYS_pipe
 *     syscall
 *     beq $a3, $zero   ; ошибки нет
 *     sw  $v0, 0($a0)  ; fd[0]
 *     sw  $v1, 4($a0)  ; fd[1]
 *     jr  $ra          ; ВОЗВРАЩАЕТ v0 == fd[0]
 *
 * То же на mipsel: разница не в порядке байт, а в ABI. На aarch64 обёртка
 * зовёт SYS_pipe2 и возвращает ноль, поэтому ни один хост-тест и ни одна
 * ARM64-установка этого не видит. d2k_sched_new (core/sched.c) ловушку уже
 * знает и проверяет `< 0`; эта проверка держит остальных конструкторов с
 * побудочной трубой, чтобы «успех» снова не прочитали как отказ.
 *
 * Как проверяется без mips-железа: httpsearch.c и httpsprobe.c компилируются
 * с -Dpipe=d2k_test_mips_pipe (тот же приём, что у httpsearch_compare_test.o),
 * а подмена ниже возвращает дескриптор, как на роутере.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "d2k_httpsearch.h"
#include "d2k_httpsprobe.h"

/* Подмена для httpsearch.o/httpsprobe.o этого теста. Сам файл собирается БЕЗ
   -Dpipe, поэтому здесь pipe() — настоящая обёртка libc. */
int d2k_test_mips_pipe(int fd[2]);
int d2k_test_mips_pipe(int fd[2]) {
    int r = pipe(fd);
    /* Успех на MIPS — положительный fd[0] (дескриптор 0 занят stdin, поэтому
       значение заведомо не нуль). Отказ — -1 с errno, как везде. */
    return r == 0 ? fd[0] : r;
}

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

static d2k_https_state probe_stub(uint8_t family, const uint8_t *addr, const char *host,
                                  uint32_t mark, char *why, size_t why_cap) {
    (void)family; (void)addr; (void)host; (void)mark;
    if (why_cap) { snprintf(why, why_cap, "заглушка"); }
    return D2K_HTTPS_SERVED;
}

int main(void) {
    /* Поиск обхода открытого HTTP: без исполнителя d2kc не заводит g_hs вовсе
       («поиск обхода HTTP не завёлся» в журнале роутера). */
    d2k_hs_runner *r = d2k_hs_runner_new();
    CHECK(r != NULL, "исполнитель поиска HTTP не завёлся при MIPS-семантике pipe()");
    if (r) {
        CHECK(d2k_hs_runner_wake_fd(r) >= 0, "у исполнителя нет дескриптора побудки");
        d2k_hs_runner_free(r);
    }
    /* Зонд HTTPS: без него вставка провайдера уходит клиенту как есть. */
    d2k_httpsprobe *p = d2k_httpsprobe_new(0x2a, probe_stub);
    CHECK(p != NULL, "зонд HTTPS не завёлся при MIPS-семантике pipe()");
    if (p) {
        CHECK(d2k_httpsprobe_wake_fd(p) >= 0, "у зонда нет дескриптора побудки");
        d2k_httpsprobe_free(p);
    }
    if (fails) { printf("test_mips_pipe: ПРОВАЛОВ %d\n", fails); return 1; }
    printf("pipe() с семантикой MIPS: конструкторы заводятся: PASS\n");
    return 0;
}
