#include <string.h>
#include "include/d2k_domain.h"
#include "include/d2k_groups.h"

int d2k_group_key_same(const d2k_group_key *a,const d2k_group_key *b) {
    return a && b && a->transport==b->transport && a->family==b->family &&
        a->shape==b->shape && !strcmp(a->probe_path,b->probe_path) &&
        !strcmp(a->ech_origin,b->ech_origin);
}
static int valid(const d2k_group_observation *o) {
    if(!o || !memchr(o->name,0,sizeof o->name) ||
       !memchr(o->plan_id,0,sizeof o->plan_id) ||
       !memchr(o->key.probe_path,0,sizeof o->key.probe_path) ||
       !memchr(o->key.ech_origin,0,sizeof o->key.ech_origin)) return 0;
    if((o->key.family!=4 && o->key.family!=6) ||
       (o->key.transport!=6 && o->key.transport!=17) || !o->key.shape) return 0;
    if(o->evidence!=1 && o->evidence!=2 && o->evidence!=4 && o->evidence!=8) return 0;
    return (o->evidence!=D2K_GROUP_BLOCKED_CONFIRMED &&
            o->evidence!=D2K_GROUP_PLAN_FAILED) || o->plan_id[0];
}
/* Normalized names, checked against PSL before entering this model. */
static int member(const char *name,const char *suffix) {
    size_t n=strlen(name),z=strlen(suffix);
    return n>=z && !strcmp(name+n-z,suffix) && (n==z || name[n-z-1]=='.');
}
static unsigned votes(const d2k_group_state *s,const char *suffix,
                       const d2k_group_observation *seed,int64_t *latest) {
    unsigned n=0; *latest=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&s->observations[i];
        if(!d2k_group_key_same(&o->key,&seed->key) || !member(o->name,suffix)) continue;
        if(o->evidence&D2K_GROUP_DIRECT_CLEAR) return 0;
        if((o->evidence&D2K_GROUP_BLOCKED_CONFIRMED) && strcmp(o->name,suffix) &&
           !strcmp(o->plan_id,seed->plan_id)) {
            n++; if(o->at>*latest) *latest=o->at;
        }
    }
    return n;
}
static void add_group(d2k_group_state *s,const char *suffix,
                      const d2k_group_observation *seed,unsigned count,int64_t at) {
    for(size_t i=0;i<s->n_groups;i++) {
        d2k_domain_group *g=&s->groups[i];
        if(!d2k_group_key_same(&g->key,&seed->key)) continue;
        if(!strcmp(g->suffix,suffix)) {
            /* Deterministic election, not catalog traversal order. */
            if(count>g->evidence_count || (count==g->evidence_count &&
               (at>g->at || (at==g->at && strcmp(seed->plan_id,g->plan_id)<0)))) {
                strcpy(g->plan_id,seed->plan_id); g->evidence_count=count; g->at=at;
            }
            return;
        }
        if(!strcmp(g->plan_id,seed->plan_id) && member(suffix,g->suffix)) return;
    }
    for(size_t i=0;i<s->n_groups;) {
        d2k_domain_group *g=&s->groups[i];
        if(d2k_group_key_same(&g->key,&seed->key) &&
           !strcmp(g->plan_id,seed->plan_id) && member(g->suffix,suffix))
            s->groups[i]=s->groups[--s->n_groups];
        else i++;
    }
    if(s->n_groups==D2K_GROUP_MAX) { s->frozen=1; return; }
    d2k_domain_group *g=&s->groups[s->n_groups++];
    memset(g,0,sizeof *g);
    strcpy(g->suffix,suffix); strcpy(g->plan_id,seed->plan_id);
    g->key=seed->key; g->evidence_count=count; g->at=at;
}
static void rebuild(d2k_group_state *s) {
    s->n_groups=0;
    for(size_t i=0;i<s->n_observations;i++) {
        const d2k_group_observation *o=&s->observations[i];
        if(!(o->evidence&D2K_GROUP_BLOCKED_CONFIRMED)) continue;
        char base[256],best[256]={0};
        if(d2k_domain_base(o->name,base)) continue;
        const char *suffix=strchr(o->name,'.');
        unsigned best_count=0; int64_t best_at=0;
        while(suffix && strlen(++suffix)>=strlen(base)) {
            int64_t at=0; unsigned count=votes(s,suffix,o,&at);
            if(count>=3) { strcpy(best,suffix); best_count=count; best_at=at; }
            suffix=strchr(suffix,'.');
        }
        if(best[0]) add_group(s,best,o,best_count,best_at);
    }
}
int d2k_group_learn(d2k_group_state *s,const d2k_group_observation *o) {
    char name[256],base[256];
    if(!s || !valid(o) || d2k_domain_normalize(o->name,name) ||
       d2k_domain_base(name,base) || s->n_groups>D2K_GROUP_MAX ||
       s->n_observations>D2K_GROUP_OBSERVATION_MAX) return -1;
    size_t slot=s->n_observations;
    for(size_t i=0;i<s->n_observations;i++)
        if(!strcmp(s->observations[i].name,name) &&
           d2k_group_key_same(&s->observations[i].key,&o->key)) { slot=i; break; }
    if(slot==s->n_observations) {
        if(s->frozen || slot==D2K_GROUP_OBSERVATION_MAX) {
            int changed=!s->frozen; s->frozen=1; return changed;
        }
        s->observations[slot]=*o; strcpy(s->observations[slot].name,name);
        s->n_observations++;
    } else {
        d2k_group_observation *old=&s->observations[slot];
        if(o->at<old->at || o->evidence==D2K_GROUP_INCONCLUSIVE) return 0;
        /* Execution failure becomes an exception, not erasure of a historic
           successful vote: other group members keep their bypass. */
        if(o->evidence==D2K_GROUP_PLAN_FAILED) {
            if(strcmp(o->plan_id,old->plan_id)) return 0;
            old->evidence|=D2K_GROUP_PLAN_FAILED; old->at=o->at;
        } else { *old=*o; strcpy(old->name,name); }
    }
    if(o->evidence!=D2K_GROUP_INCONCLUSIVE) rebuild(s);
    return 1;
}
const d2k_domain_group *d2k_group_match(const d2k_group_state *s,
                                     const char *name,const d2k_group_key *key) {
    char norm[256];
    if(!s || !key || d2k_domain_normalize(name,norm) ||
       s->n_groups>D2K_GROUP_MAX || s->n_observations>D2K_GROUP_OBSERVATION_MAX) return NULL;
    const d2k_domain_group *best=NULL;
    for(size_t i=0;i<s->n_groups;i++) {
        const d2k_domain_group *g=&s->groups[i];
        if(!d2k_group_key_same(&g->key,key) || !member(norm,g->suffix)) continue;
        int excluded=0;
        for(size_t j=0;j<s->n_observations;j++) {
            const d2k_group_observation *o=&s->observations[j];
            if(strcmp(o->name,norm) || !d2k_group_key_same(&o->key,key)) continue;
            if((o->evidence&D2K_GROUP_DIRECT_CLEAR) ||
               ((o->evidence&D2K_GROUP_PLAN_FAILED) && !strcmp(o->plan_id,g->plan_id))) excluded=1;
        }
        if(!excluded && (!best || strlen(g->suffix)>strlen(best->suffix))) best=g;
    }
    return best;
}
