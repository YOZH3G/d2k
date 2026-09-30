#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/d2k_groups.h"
static int failed;
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"groups:%d: %s\n",__LINE__,#c); failed++; } } while(0)
static d2k_group_key modern={6,4,1,"",""};
static void observe(d2k_group_state *s, const char *name, const char *plan,
                    unsigned evidence, d2k_group_key key) {
    d2k_group_observation o={0};
    snprintf(o.name,sizeof o.name,"%s",name);
    snprintf(o.plan_id,sizeof o.plan_id,"%s",plan);
    o.evidence=evidence; o.key=key; o.at=100;
    CHECK(d2k_group_learn(s,&o)>=0);
}
int main(void) {
    d2k_group_key long_key;
    char path_a[512],path_b[512];
    memset(path_a,'a',sizeof path_a); path_a[0]='/'; path_a[300]=0;
    memcpy(path_b,path_a,sizeof path_b); path_b[299]='b';
    CHECK(d2k_group_key_make(&long_key,6,4,1,path_a,"")==-1);
    CHECK(d2k_group_key_make(&long_key,6,4,1,path_b,"")==-1);
    CHECK(d2k_group_key_make(&long_key,6,4,1,"/public/site.css","")==0 &&
          !strcmp(long_key.probe_path,"/public/site.css"));
    d2k_group_state *s=calloc(1,sizeof *s);
    CHECK(s!=NULL); if(!s) return 1;
    /* Counting requests rather than independent host evidence must fail. */
    for(int i=0;i<5;i++) observe(s,"meet.google.com","plan-a",1,modern);
    CHECK(s->n_groups==0 && s->n_observations==1);
    observe(s,"rr1.googlevideo.com","plan-a",1,modern);
    observe(s,"rr2.googlevideo.com","plan-a",1,modern);
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    observe(s,"rr3.googlevideo.com","plan-a",1,modern);
    const d2k_domain_group *g=d2k_group_match(s,"rr-new.googlevideo.com",&modern);
    CHECK(g && !strcmp(g->suffix,"googlevideo.com") && !strcmp(g->plan_id,"plan-a"));
    CHECK(!d2k_group_match(s,"evilgooglevideo.com",&modern));
    CHECK(!d2k_group_match(s,"google.com",&modern));
    size_t before=s->n_observations;
    for(int i=0;i<100;i++) CHECK(d2k_group_match(s,"a.b.new.googlevideo.com",&modern));
    CHECK(s->n_observations==before); /* Lookup does not enrol every CDN name. */
    d2k_group_key other=modern;
    other.family=6; CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; other.shape=2; CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; other.transport=17; other.shape=3;
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; strcpy(other.probe_path,"/large.css");
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other));
    other=modern; strcpy(other.ech_origin,"origin.example.com"); other.shape=6;
    CHECK(!d2k_group_match(s,"rr-new.googlevideo.com",&other));
    observe(s,"rr1.googlevideo.com","plan-a",8,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    observe(s,"rr1.googlevideo.com","plan-a",4,modern);
    CHECK(!d2k_group_match(s,"rr1.googlevideo.com",&modern));
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    /* A clean sibling prevents broadening, but allows the nested CDN branch. */
    observe(s,"www.example.com","",2,modern);
    observe(s,"a.cdn.example.com","plan-b",1,modern);
    observe(s,"b.cdn.example.com","plan-b",1,modern);
    observe(s,"c.cdn.example.com","plan-b",1,modern);
    g=d2k_group_match(s,"new.cdn.example.com",&modern);
    CHECK(g && !strcmp(g->suffix,"cdn.example.com"));
    CHECK(!d2k_group_match(s,"api.example.com",&modern));
    CHECK(!d2k_group_match(s,"www.example.com",&modern));
    /* Independent hosting tenants must never collapse at github.io. */
    observe(s,"a.github.io","plan-c",1,modern);
    observe(s,"b.github.io","plan-c",1,modern);
    observe(s,"c.github.io","plan-c",1,modern);
    CHECK(!d2k_group_match(s,"new.github.io",&modern));
    /* A different successful plan is not a vote for the elected candidate. */
    observe(s,"a.mixed.net","plan-a",1,modern);
    observe(s,"b.mixed.net","plan-b",1,modern);
    observe(s,"c.mixed.net","plan-c",1,modern);
    CHECK(!d2k_group_match(s,"new.mixed.net",&modern));
    /* A proven clean member becomes an exception, not a family-wide outage. */
    observe(s,"clean.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    CHECK(!d2k_group_match(s,"clean.googlevideo.com",&modern));
    observe(s,"clean.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    observe(s,"clean.googlevideo.com","plan-a",1,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    d2k_group_observation invalid={0};
    strcpy(invalid.name,"a.example.com"); invalid.key=modern;
    invalid.evidence=1;
    CHECK(d2k_group_learn(s,&invalid)==-1); /* no authenticated plan */
    strcpy(invalid.plan_id,"plan-a");
    invalid.key.shape=255;
    CHECK(d2k_group_learn(s,&invalid)==-1);
    invalid.key=modern; invalid.key.transport=17;
    CHECK(d2k_group_learn(s,&invalid)==-1);
    invalid.key=modern;
    memset(invalid.name,'x',sizeof invalid.name);
    CHECK(d2k_group_learn(s,&invalid)==-1); /* no NUL */
    for(int i=0;s->n_observations<D2K_GROUP_OBSERVATION_MAX;i++) {
        char name[256]; snprintf(name,sizeof name,"h%d.fill.example.net",i);
        observe(s,name,"plan-z",8,modern);
    }
    observe(s,"overflow.example.net","plan-z",1,modern);
    CHECK(s->frozen && s->n_observations==D2K_GROUP_OBSERVATION_MAX);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    CHECK(!d2k_group_match(s,"unknown.fill.example.net",&modern));
    observe(s,"overflow-clean.googlevideo.com","",2,modern);
    CHECK(!d2k_group_match(s,"overflow-clean.googlevideo.com",&modern));
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    CHECK(s->n_observations==D2K_GROUP_OBSERVATION_MAX);
    observe(s,"rr2.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    CHECK(!d2k_group_match(s,"rr2.googlevideo.com",&modern));
    observe(s,"rr3.googlevideo.com","",2,modern);
    CHECK(d2k_group_match(s,"rr-new.googlevideo.com",&modern));
    /* A full budget of exceptions can still contain historic positive votes.
       Never keep an area active when a new exclusion cannot be retained. */
    memset(s,0,sizeof *s);
    for(int i=0;i<3;i++) {
        char name[256]; snprintf(name,sizeof name,"h%d.googlevideo.com",i);
        observe(s,name,"plan-a",1,modern);
    }
    for(int i=0;i<3;i++) {
        char name[256]; snprintf(name,sizeof name,"h%d.googlevideo.com",i);
        observe(s,name,"plan-a",4,modern);
    }
    for(int i=3;i<D2K_GROUP_OBSERVATION_MAX;i++) {
        char name[256]; snprintf(name,sizeof name,"clean%d.example.net",i);
        observe(s,name,"",2,modern);
    }
    CHECK(d2k_group_match(s,"new.googlevideo.com",&modern));
    observe(s,"unrecordable.googlevideo.com","",2,modern);
    CHECK(s->n_groups==0);
    CHECK(!d2k_group_match(s,"new.googlevideo.com",&modern));
    CHECK(d2k_group_restore(s)==0 && s->n_groups==0);
    free(s);
    if(!failed) puts("groups: passed");
    return failed?1:0;
}
