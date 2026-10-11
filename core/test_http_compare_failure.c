/* Exercise the public controller path with a failed Plan compilation,
   including the compiler's allocation-error contract. Only httpsearch's
   compiler call is redirected; all other Plan compilation remains real. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include "d2k_plantlv.h"
static int compare_fault, compare_faults;
int d2k_test_compare_tlv(const char *text,uint8_t *out,size_t cap,
    size_t *out_len,char *err,size_t errcap) {
    if(compare_fault) {
        compare_faults++;
        snprintf(err,errcap,"injected compiler allocation failure");
        return -1;
    }
    return d2k_plan_text_to_tlv(text,out,cap,out_len,err,errcap);
}
#define D2K_TEST_HTTP_COMPARE_FAILURE 1
#define main httpsearch_normal_main
#include "test_httpsearch.c"
#undef main
int main(void) {
    test_live_failure_alias();
    CHECK(compare_faults>=2,"comparison compiler error was exercised for both aliases");
    printf("test_http_compare_failure: failures %d\n",fails);
    return fails ? 1 : 0;
}
