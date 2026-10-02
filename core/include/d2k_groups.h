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
/* Additional provenance bit: clean evidence found after area admission.
 * It blocks this exact member, not already learned unrelated siblings. */
#define D2K_GROUP_ADMITTED_EXCEPTION 16u
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
    int frozen, disabled;
    /* Wall-clock seconds of the newest evidence when areas were disabled:
       plain votes at or before it are dropped on re-enable. */
    int64_t disabled_at;
} d2k_group_state;
int d2k_group_key_same(const d2k_group_key *a, const d2k_group_key *b);
int d2k_group_key_make(d2k_group_key *key, uint8_t transport, uint8_t family,
    uint8_t shape, const char *path, const char *origin);
int d2k_group_learn(d2k_group_state *s, const d2k_group_observation *o);
/* Validate saved observations and derive active areas, never trust a saved
   suffix alone. Preserves failure exceptions and frozen admission state. */
int d2k_group_restore(d2k_group_state *s);
const d2k_domain_group *d2k_group_match(const d2k_group_state *s,
                                     const char *name, const d2k_group_key *key);
#endif
