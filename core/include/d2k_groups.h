#ifndef D2K_GROUPS_H
#define D2K_GROUPS_H
#include <stddef.h>
#include <stdint.h>
#define D2K_GROUP_MAX 64
#define D2K_GROUP_OBSERVATION_MAX 256
typedef struct {
    uint8_t transport, family, shape;
    char probe_path[256], ech_origin[256];
} d2k_group_key;
enum {
    D2K_GROUP_BLOCKED_CONFIRMED=1,
    D2K_GROUP_DIRECT_CLEAR=2,
    D2K_GROUP_PLAN_FAILED=4,
    D2K_GROUP_INCONCLUSIVE=8
};
typedef struct {
    char name[256], plan_id[40];
    d2k_group_key key;
    unsigned evidence;
    int64_t at;
} d2k_group_observation;
typedef struct {
    char suffix[256], plan_id[40];
    d2k_group_key key;
    unsigned evidence_count;
    int64_t at;
} d2k_domain_group;
typedef struct {
    d2k_domain_group groups[D2K_GROUP_MAX];
    d2k_group_observation observations[D2K_GROUP_OBSERVATION_MAX];
    size_t n_groups, n_observations;
    int frozen;
} d2k_group_state;
int d2k_group_key_same(const d2k_group_key *a, const d2k_group_key *b);
int d2k_group_learn(d2k_group_state *s, const d2k_group_observation *o);
const d2k_domain_group *d2k_group_match(const d2k_group_state *s,
                                     const char *name, const d2k_group_key *key);
#endif
