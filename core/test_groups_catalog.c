#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "include/d2k_catalog.h"
#include "include/d2k_groups.h"
static int failed;
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"group-catalog:%d: %s\n",__LINE__,#c); failed++; } } while(0)
int main(void) {
    char path[]="/tmp/d2k-groups-catalog-XXXXXX",err[256];
    int fd=mkstemp(path); CHECK(fd>=0); if(fd<0) return 1; close(fd);
    d2k_catalog a={0},b={0};
    a.groups=calloc(1,sizeof *a.groups);
    CHECK(a.groups!=NULL); if(!a.groups) { unlink(path); return 1; }
    a.boxes=calloc(1,sizeof *a.boxes); a.n_boxes=1;
    CHECK(a.boxes!=NULL); if(!a.boxes) { d2k_catalog_free(&a); unlink(path); return 1; }
    strcpy(a.boxes[0].id,"box-test");
    a.boxes[0].plans=calloc(1,sizeof *a.boxes[0].plans); a.boxes[0].n_plans=1;
    CHECK(a.boxes[0].plans!=NULL); if(!a.boxes[0].plans) { a.boxes[0].n_plans=0; d2k_catalog_free(&a); unlink(path); return 1; }
    strcpy(a.boxes[0].plans[0].id,"plan-test");
    strcpy(a.boxes[0].plans[0].proto,"tls");
    a.boxes[0].plans[0].text=strdup("opaque-test-plan");
    a.boxes[0].plans[0].enabled=1;
    d2k_group_key key={6,4,1,"",""};
    /* §3.7: five voters, so the two exceptions below (rr0 failed, rr1
       clear) stay a minority and the family legitimately survives. */
    for(int i=0;i<5;i++) {
        d2k_group_observation o={0};
        snprintf(o.name,sizeof o.name,"rr%d.googlevideo.com",i);
        strcpy(o.plan_id,"plan-test"); o.key=key; o.evidence=1; o.at=123;
        CHECK(d2k_group_learn(a.groups,&o)==1);
    }
    d2k_group_observation o=a.groups->observations[0]; o.evidence=4; o.at=124;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_observations==5 && b.groups->n_groups==1);
    CHECK(b.groups && d2k_group_match(b.groups,"new.googlevideo.com",&key));
    CHECK(b.groups && !d2k_group_match(b.groups,"rr0.googlevideo.com",&key));
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1);
    d2k_catalog_free(&b);
    memset(&o,0,sizeof o); strcpy(o.name,"clean.googlevideo.com");
    o.key=key; o.evidence=2; o.at=125;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && d2k_group_match(b.groups,"new.googlevideo.com",&key));
    CHECK(b.groups && !d2k_group_match(b.groups,"clean.googlevideo.com",&key));
    d2k_catalog_free(&b);
    o=a.groups->observations[1]; o.evidence=2; o.at=126;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && d2k_group_match(b.groups,"new.googlevideo.com",&key));
    CHECK(b.groups && !d2k_group_match(b.groups,"rr1.googlevideo.com",&key));
    d2k_catalog_free(&b);
    a.groups->frozen=1;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0 && b.groups && b.groups->frozen);
    CHECK(b.groups && d2k_group_match(b.groups,"never-seen.googlevideo.com",&key));
    d2k_catalog_free(&b);
    /* §3.7: a third degraded voter makes them the majority → retired,
       also after save/load. */
    memset(&o,0,sizeof o); strcpy(o.name,"rr2.googlevideo.com");
    o.key=key; o.evidence=2; o.at=127;
    CHECK(d2k_group_learn(a.groups,&o)==1);
    CHECK(!d2k_group_match(a.groups,"new.googlevideo.com",&key));
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->n_groups==0 &&
          !d2k_group_match(b.groups,"new.googlevideo.com",&key));
    d2k_catalog_free(&b);
    /* Disabled without a stored moment (older catalogs) loads as 0. */
    a.groups->disabled=1;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->disabled && b.groups->disabled_at==0);
    d2k_catalog_free(&b);
    a.groups->disabled_at=1700000000;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && b.groups->disabled_at==1700000000);
    CHECK(b.groups && b.groups->disabled && b.groups->n_groups==0);
    CHECK(b.n_boxes==1 && b.boxes[0].n_plans==1 && b.boxes[0].plans[0].enabled);
    d2k_catalog_free(&b);
    a.groups->disabled=0;
    a.boxes[0].plans[0].enabled=0;
    CHECK(d2k_catalog_save(&a,path,err,sizeof err)==0);
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0);
    CHECK(b.groups && !d2k_group_match(b.groups,"new.googlevideo.com",&key));
    d2k_catalog_free(&a); d2k_catalog_free(&b);
    FILE *f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[],\"domain_observations\":[{\"name\":\"a.example.com\",\"evidence\":255}]}",f); fclose(f); }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)!=0);
    d2k_catalog_free(&b);
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) {
        fputs("{\"boxes\":[],\"domain_observations\":[",f);
        for(int i=0;i<=D2K_GROUP_OBSERVATION_MAX;i++) {
            if(i) fputc(',',f);
            fprintf(f,"{\"name\":\"h%d.example.com\",\"transport\":6,\"family\":4,\"shape\":1,\"evidence\":2}",i);
        }
        fputs("]}",f); fclose(f);
    }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)!=0);
    d2k_catalog_free(&b);
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[],\"domain_groups\":[{\"suffix\":\"google.com\",\"plan_id\":\"forged\"}]}",f); fclose(f); }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0 && !b.groups);
    d2k_catalog_free(&b); /* derived snapshot cannot create an executable rule */
    f=fopen(path,"w"); CHECK(f!=NULL);
    if(f) { fputs("{\"boxes\":[]}",f); fclose(f); }
    CHECK(d2k_catalog_load(path,&b,err,sizeof err)==0 && !b.groups);
    d2k_catalog_free(&b); unlink(path);
    if(!failed) puts("group catalog: passed");
    return failed?1:0;
}
