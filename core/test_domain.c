#include <stdio.h>
#include <string.h>
#include "include/d2k_domain.h"

static int failed;
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"domain:%d: %s\n",__LINE__,#c); failed++; } } while(0)
int main(void) {
    /* Wrong suffix depth would merge distinct registrants/hosting tenants. */
    static const struct { const char *name, *base; } cases[] = {
        {"rr1.googlevideo.com","googlevideo.com"},
        {"a.b.cdninstagram.com","cdninstagram.com"},
        {"MEET.Google.COM.","google.com"},
        {"a.example.co.uk","example.co.uk"},
        {"x.tenant.github.io","tenant.github.io"},
        {"x.tenant.blogspot.com","tenant.blogspot.com"},
        {"x.a.b.ck","a.b.ck"}, {"x.www.ck","www.ck"},
        {"x.city.kawasaki.jp","city.kawasaki.jp"},
        {"com",NULL},{"co.uk",NULL},{"github.io",NULL},
        {"a.b.unknown-d2k-suffix",NULL}, {"127.0.0.1",NULL},
        {"2001:db8::1",NULL},{"a..com",NULL},{"-bad.com",NULL},
        {"bad-.com",NULL},{"bad_name.com",NULL},{"",NULL}
    };
    char out[256];
    for (size_t i=0;i<sizeof cases/sizeof cases[0];i++) {
        int rc=d2k_domain_base(cases[i].name,out);
        CHECK(cases[i].base ? rc==0 && !strcmp(out,cases[i].base) : rc==-1);
    }
    CHECK(d2k_domain_member("rr.googlevideo.com","googlevideo.com"));
    CHECK(d2k_domain_member("a.b.googlevideo.com","googlevideo.com"));
    CHECK(d2k_domain_member("GOOGLEVIDEO.COM.","googlevideo.com"));
    CHECK(!d2k_domain_member("evilgooglevideo.com","googlevideo.com"));
    CHECK(!d2k_domain_member("googlevideo.com.evil.com","googlevideo.com"));
    CHECK(!d2k_domain_member("googlevideo.com","com"));
    CHECK(!d2k_domain_member("a..googlevideo.com","googlevideo.com"));
    CHECK(d2k_domain_base(NULL,out)==-1);
    if (!failed) puts("domain: passed");
    return failed ? 1:0;
}
