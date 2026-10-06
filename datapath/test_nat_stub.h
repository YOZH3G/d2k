/* test_nat_stub.h — «таблицы соединений нет» для тестов датапата.
 *
 * Таблица conntrack хоста не должна решать вердикт теста: на Linux, где
 * nf_conntrack загружен (CI, Docker), чтение настоящей таблицы не находит
 * тестовых потоков, и планы отказывались «поток не ведётся conntrack». На
 * macOS таблицы нет, и тесты проходили — поэтому поломка на Linux не была
 * видна. Тесты ставят D2K_TEST_NAT_NO_TABLE() первой строкой main; случаи,
 * где NAT важен, ставят свой stub поверх. */
#ifndef D2K_TEST_NAT_STUB_H
#define D2K_TEST_NAT_STUB_H

#include "d2k_nat.h"

static int test_nat_no_table(const char *path, uint8_t proto, uint32_t src_ip,
                             uint16_t src_port, uint32_t dst_ip, uint16_t dst_port,
                             uint32_t *out_src, uint16_t *out_sport) {
    (void)path; (void)proto; (void)src_ip; (void)src_port; (void)dst_ip;
    (void)dst_port; (void)out_src; (void)out_sport;
    return 1;
}
static int test_nat_no_table_family(const char *path, uint8_t proto,
    const uint8_t *src, uint16_t sport, const uint8_t *dst, uint16_t dport,
    uint8_t family, uint8_t *out_src, uint16_t *out_sport) {
    (void)path; (void)proto; (void)src; (void)sport; (void)dst; (void)dport;
    (void)family; (void)out_src; (void)out_sport;
    return 1;
}
#define D2K_TEST_NAT_NO_TABLE() \
    do { d2k_nat_hook = test_nat_no_table; \
         d2k_nat_family_hook = test_nat_no_table_family; } while (0)

#endif
