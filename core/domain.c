#include <stddef.h>
#include <string.h>
#include "include/d2k_domain.h"
#include "profiles/psl_index.h"

int d2k_domain_normalize(const char *name, char out[256]) {
    if (!name || !out) return -1;
    size_t n = strlen(name);
    if (n && name[n-1] == '.') n--;
    if (!n || n > 253) return -1;
    size_t label = 0;
    int nonnumeric = 0;
    for (size_t i=0; i<n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c >= 'A' && c <= 'Z') c += 'a'-'A';
        if (c == '.') {
            if (!label || out[i-1] == '-') return -1;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return -1;
            if ((!label && c == '-') || ++label > 63) return -1;
            if (c < '0' || c > '9') nonnumeric = 1;
        }
        out[i] = (char)c;
    }
    if (!label || out[n-1] == '-' || !nonnumeric) return -1;
    out[n] = 0;
    return 0;
}

static int rule_exists(const char *rule) {
    size_t lo=0, hi=sizeof d2k_psl_offsets/sizeof d2k_psl_offsets[0];
    while (lo<hi) {
        size_t mid=lo+(hi-lo)/2;
        int cmp=strcmp(rule,d2k_psl_blob+d2k_psl_offsets[mid]);
        if (!cmp) return 1;
        if (cmp<0) hi=mid; else lo=mid+1;
    }
    return 0;
}

int d2k_domain_base(const char *name, char out[256]) {
    char norm[256], pattern[258];
    if (!out || d2k_domain_normalize(name,norm)) return -1;
    /* Longest rule wins; exceptions outrank wildcard, unknown TLD is unsafe. */
    size_t starts[128], count=1, suffix_count=0, exception_count=0;
    starts[0]=0;
    for (size_t i=0; norm[i]; i++) if (norm[i]=='.') starts[count++]=i+1;
    for (size_t i=0; i<count; i++) {
        const char *s=norm+starts[i];
        size_t labels=count-i;
        pattern[0]='!'; strcpy(pattern+1,s);
        if (rule_exists(pattern) && labels>exception_count) exception_count=labels;
        if (rule_exists(s) && labels>suffix_count) suffix_count=labels;
        if (i>0) {
            pattern[0]='*'; pattern[1]='.'; strcpy(pattern+2,s);
            if (rule_exists(pattern) && labels+1>suffix_count) suffix_count=labels+1;
        }
    }
    if (exception_count) suffix_count=exception_count-1;
    if (!suffix_count || count<=suffix_count) return -1;
    strcpy(out,norm+starts[count-suffix_count-1]);
    return 0;
}

int d2k_domain_member(const char *name, const char *suffix) {
    char n[256], s[256], base[256];
    if (d2k_domain_normalize(name,n) || d2k_domain_normalize(suffix,s) ||
        d2k_domain_base(s,base)) return 0;
    size_t nl=strlen(n), sl=strlen(s);
    return nl>=sl && !strcmp(n+nl-sl,s) && (nl==sl || n[nl-sl-1]=='.');
}
