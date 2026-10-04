#ifndef D2K_UPDATE_H
#define D2K_UPDATE_H
#include <stddef.h>
#include <stdint.h>

#define D2KU_INDEX_MAX 65536u
#define D2KU_MANIFEST_MAX 1048576u
#define D2KU_FILES_MAX 512u
#define D2KU_PACKAGES_MAX 9u
#define D2KU_KEYS_MAX 8u
#define D2KU_ID_MAX 64u
#define D2KU_PATH_MAX 240u
#define D2KU_NOTES_MAX 16384u
#define D2KU_VERSION_MAX 64u
#define D2KU_ABI_MAX 8u

typedef enum { D2KU_OK, D2KU_INVALID, D2KU_UNTRUSTED, D2KU_EXPIRED,
    D2KU_REPLAY, D2KU_INCOMPATIBLE, D2KU_BUSY, D2KU_IO, D2KU_NETWORK,
    D2KU_TIME, D2KU_HEALTH } d2ku_rc;
typedef struct d2ku_ctx d2ku_ctx;
typedef struct d2ku_manifest d2ku_manifest;
typedef struct d2ku_index d2ku_index;
typedef struct d2ku_status d2ku_status;
typedef struct d2ku_journal d2ku_journal;
typedef struct d2ku_policy d2ku_policy;
typedef struct d2ku_clock d2ku_clock;
typedef struct d2ku_request d2ku_request;

struct d2ku_clock {
    void *arg;
    /* wall returns TIME unless UTC is trustworthy; monotonic is nanoseconds. */
    d2ku_rc (*wall)(void *arg, int64_t *utc_seconds);
    d2ku_rc (*monotonic)(void *arg, uint64_t *nanoseconds);
};
typedef struct {
    unsigned char public_key[32];
    int64_t not_before, not_after; /* inclusive start, exclusive end */
} d2ku_key;
struct d2ku_ctx {
    int root_dirfd; /* production: verified /opt/d2k dirfd */
    d2ku_clock clock;
    char abi[D2KU_ABI_MAX + 1];
    uint64_t updater_version, wire_version, state_version;
    d2ku_key trust[D2KU_KEYS_MAX];
    size_t trust_count;
    uint64_t accepted_sequence;
    unsigned char accepted_index_sha256[32];
    int has_accepted_index;
    /* Owned by caller; no hidden allocations or persistence in verification. */
    void *io_arg;
    d2ku_rc (*sync_fd)(void *arg, int fd);
    void *service_arg;
    d2ku_rc (*service)(void *arg, const char *fixed_action);
};
struct d2ku_index {
    uint64_t schema, sequence;
    int64_t issued_at, expires_at;
    char channel[7]; size_t channel_len;
    char release_id[D2KU_ID_MAX + 1]; size_t release_id_len;
    unsigned char manifest_sha256[32], document_sha256[32];
};
typedef struct {
    char path[D2KU_PATH_MAX + 1]; size_t path_len;
    uint64_t size;
    uint32_t mode; /* 0644 or 0755 */
    unsigned char sha256[32];
} d2ku_file;
typedef struct {
    char abi[D2KU_ABI_MAX + 1]; size_t abi_len;
    char artifact[D2KU_PATH_MAX + 1]; size_t artifact_len;
    uint64_t size;
    unsigned char sha256[32];
    size_t file_offset, file_count; /* range within manifest.files */
} d2ku_package;
struct d2ku_manifest {
    uint64_t schema, min_updater, wire, state;
    char release_id[D2KU_ID_MAX + 1]; size_t release_id_len;
    char version[D2KU_VERSION_MAX + 1]; size_t version_len;
    char commit[41]; size_t commit_len;
    int64_t built_at;
    char notes[D2KU_NOTES_MAX + 1]; size_t notes_len;
    d2ku_package packages[D2KU_PACKAGES_MAX]; size_t package_count;
    d2ku_file files[D2KU_FILES_MAX]; size_t file_count;
    d2ku_key signing_keys[D2KU_KEYS_MAX]; size_t signing_key_count;
    unsigned char document_sha256[32];
    size_t signing_key_index; /* signer in ctx.trust, for transition overlap */
};
/* Verify original bytes before JSON parsing; output and context unchanged on
 * failure, except manifest INCOMPATIBLE for a fully validated schema=1 document:
 * that exposes authenticated metadata for display, but MUST NOT be installed.
 * Unknown schema leaves output unchanged. Output owns all data.
 * Callers must durably accept index
 * sequence/hash and transition keys independently of runtime rollback. */
d2ku_rc d2ku_verify_index(d2ku_ctx *, const void *, size_t,
    const unsigned char sig[64], d2ku_index *);
d2ku_rc d2ku_verify_manifest(d2ku_ctx *, const void *, size_t,
    const unsigned char sig[64], d2ku_manifest *);
#endif
