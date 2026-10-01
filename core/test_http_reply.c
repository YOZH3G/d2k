#include <stdio.h>
#include <string.h>
#include "d2k_http_reply.h"

static int fails;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); fails++; } } while (0)
int main(void) {
    struct { int code; const char *location, *body; int encoding; d2k_http_outcome want; } cases[] = {
        {200,"","hello",0,D2K_HTTP_POSITIVE},
        {304,"","",0,D2K_HTTP_POSITIVE},
        {302,"/login","",0,D2K_HTTP_POSITIVE},
        {302,"https://www.google.com/","",0,D2K_HTTP_NEUTRAL},
        {302,"https://warning.rt.ru/","",0,D2K_HTTP_BLOCKED},
        {302,"//eais.rkn.gov.ru/blocked","",0,D2K_HTTP_BLOCKED},
        {302,"https://WARNING.RT.RU.:443/","",0,D2K_HTTP_BLOCKED},
        {302,"https://warning.rt.ru.evil.example/","",0,D2K_HTTP_NEUTRAL},
        {302,"https://other.example/warning.rt.ru","",0,D2K_HTTP_NEUTRAL},
        {403,"","SparkNotes account expired",0,D2K_HTTP_NEUTRAL},
        {403,"","access blocked by rkn",0,D2K_HTTP_BLOCKED},
        {403,"","access blocked by rkn",1,D2K_HTTP_NEUTRAL},
        {403,"","https://eais.rkn.gov.ru/",0,D2K_HTTP_BLOCKED},
        {403,"","https://eais.rkn.gov.ru.evil.example/",0,D2K_HTTP_NEUTRAL},
        {403,"","not-eais.rkn.gov.ru",0,D2K_HTTP_NEUTRAL},
        {200,"","article: access blocked by rkn",0,D2K_HTTP_POSITIVE},
        {451,"","",0,D2K_HTTP_LEGAL_DENIAL},
    };
    for (size_t i=0;i<sizeof cases/sizeof cases[0];i++) {
        d2k_http_reply_result r=d2k_http_reply_classify(cases[i].code,cases[i].location,
            cases[i].encoding,(const unsigned char *)cases[i].body,
            strlen(cases[i].body),strlen(cases[i].body));
        CHECK(r.outcome==cases[i].want);
    }
    const char *cut="eais.rkn.gov.ru";
    CHECK(d2k_http_reply_classify(403,"",0,(const unsigned char *)cut,
        strlen(cut),strlen(cut)+20).outcome==D2K_HTTP_NEUTRAL);
    CHECK(d2k_http_reply_classify(403,"",0,NULL,0,0).outcome==D2K_HTTP_NEUTRAL);
    for (size_t i=0;i<6;i++) {
        char location[160];
        snprintf(location,sizeof location,"https://user@%s:443/blocked",d2k_http_portal(i));
        CHECK(d2k_http_reply_classify(307,location,0,NULL,0,0).outcome==D2K_HTTP_BLOCKED);
        snprintf(location,sizeof location,"https://%s@ordinary.example/",d2k_http_portal(i));
        CHECK(d2k_http_reply_classify(307,location,0,NULL,0,0).outcome==D2K_HTTP_NEUTRAL);
    }
    const unsigned char binary[] = {0,' ','e','a','i','s','.','r','k','n','.','g','o','v','.','r','u','/'};
    CHECK(d2k_http_reply_classify(403,"",0,binary,sizeof binary,sizeof binary).outcome==D2K_HTTP_BLOCKED);
    if (fails) return 1;
    puts("HTTP reply classifier: donor signatures, neutral redirects, encoding and boundaries passed");
    return 0;
}
