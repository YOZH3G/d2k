#ifndef D2K_UPDATE_H
#define D2K_UPDATE_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

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
#define D2KU_HOSTS_MAX 8u
#define D2KU_HOST_MAX 253u
#define D2KU_CA_PATH_MAX 1024u
#define D2KU_BOOT_ID_MAX 64u
#define D2KU_TIMEZONE_MAX 128u
#define D2KU_CHECK_TTL_MS UINT64_C(900000)

typedef enum { D2KU_OK, D2KU_INVALID, D2KU_UNTRUSTED, D2KU_EXPIRED,
    D2KU_REPLAY, D2KU_INCOMPATIBLE, D2KU_BUSY, D2KU_IO, D2KU_NETWORK,
    D2KU_TIME, D2KU_HEALTH, D2KU_ABSENT, D2KU_RECOVERY } d2ku_rc;
typedef struct d2ku_ctx d2ku_ctx;
typedef struct d2ku_manifest d2ku_manifest;
typedef struct d2ku_index d2ku_index;
typedef struct d2ku_status d2ku_status;
typedef struct d2ku_journal d2ku_journal;
typedef struct d2ku_policy d2ku_policy;
typedef struct d2ku_clock d2ku_clock;
typedef struct d2ku_request d2ku_request;

typedef struct {
    int64_t utc_seconds;
    uint64_t mono_ms;
    int32_t local_date; /* Gregorian YYYYMMDD in router timezone */
    unsigned local_minute; /* 0..1439 */
    char boot_id[D2KU_BOOT_ID_MAX + 1];
    char timezone[D2KU_TIMEZONE_MAX + 1]; /* router POSIX TZ / zone identifier */
    int synchronized; /* exactly 1: platform explicitly confirmed sync */
} d2ku_clock_sample;

struct d2ku_clock {
    void *arg;
    /* wall returns TIME unless UTC is trustworthy; monotonic is nanoseconds. */
    d2ku_rc (*wall)(void *arg, int64_t *utc_seconds);
    d2ku_rc (*monotonic)(void *arg, uint64_t *nanoseconds);
    /* Coherent snapshot from same platform clock as wall/monotonic. The daemon
     * owns the adapter: capture UTC/monotonic/boot, derive local calendar using
     * router TZ, report explicit sync (unknown != synchronized). No guessing.
     * wall MUST apply the same trust/floor checks as d2ku_read_clock. */
    d2ku_rc (*snapshot)(void *arg, d2ku_clock_sample *);
    int64_t build_timestamp, last_accepted_timestamp; /* trusted UTC floors */
};
struct d2ku_policy {
    int enabled;
    int32_t selected_date, last_attempt_date; /* durable date high-water marks */
    unsigned selected_minute; /* 180..299, saved once per selected_date */
    int has_quarantined_release;
    unsigned char quarantined_release_sha256[32]; /* exact manifest hash */
};
#define D2KU_SERVICE_DATAPATH UINT64_C(1)
#define D2KU_SERVICE_CORE UINT64_C(2)
#define D2KU_SERVICE_PANEL UINT64_C(4)
#define D2KU_SERVICE_TELEGRAM UINT64_C(8)
#define D2KU_VALIDATION_MS UINT64_C(120000)
#define D2KU_HEARTBEAT_MS UINT64_C(10000)
typedef struct {
    pid_t pid;
    uint64_t start_ticks, heartbeat_mono_ms;
    char release_id[D2KU_ID_MAX + 1], peer_release_id[D2KU_ID_MAX + 1];
    char boot_id[D2KU_BOOT_ID_MAX + 1];
    uint64_t wire;
    int executable_matches, peer_connected, ready, external_available;
} d2ku_health_observation;
struct d2ku_status {
    int health_observing, installation_healthy, health_complete, external_available;
    uint64_t health_since_ms, health_last_ms;
    char health_transaction[D2KU_ID_MAX + 1], health_boot[D2KU_BOOT_ID_MAX + 1];
    char health_release[D2KU_ID_MAX + 1];
    unsigned char health_manifest_sha256[32];
    uint64_t health_services;
    pid_t health_pid[4];
    uint64_t health_start_ticks[4];
    int has_check, check_in_flight;
    uint64_t checked_mono_ms;
    char checked_boot_id[D2KU_BOOT_ID_MAX + 1];
    char observed_boot_id[D2KU_BOOT_ID_MAX + 1];
    d2ku_rc check_result;
    int has_success;
    int64_t last_success_utc; /* retained on later failed checks */
};

/* No I/O/persistence. read_clock rejects unknown sync, invalid calendar/boot/TZ
 * and wall below either UTC floor. Output unchanged on failure. Manual install
 * must use this gate too; force check never bypasses signature time checks. */
d2ku_rc d2ku_read_clock(const d2ku_clock *, d2ku_clock_sample *);
/* Caller supplies an unbiased random offset 0..119. Save returned choice
 * durably before relying on it. Existing date keeps its minute; older rejected. */
d2ku_rc d2ku_select_minute(d2ku_policy *, int32_t date, unsigned random_offset);
/* Schedule only. Automatic install needs BOTH auto_due and release_allowed.
 * Recheck immediately before switch after download; begun switch/validation/
 * rollback is completed regardless of window end. No manual date consumption. */
int d2ku_auto_due(const d2ku_policy *, const d2ku_clock *);
int d2ku_auto_release_allowed(const d2ku_policy *, const unsigned char hash[32]);
/* Caller serializes attempts and durably fsyncs resulting policy BEFORE starting
 * auto install. Failure to persist means do not install. Not for manual use. */
d2ku_rc d2ku_mark_auto_attempt(d2ku_policy *, const d2ku_clock *);
/* Observe boot before check_due. Cache is volatile; every boot requires a check.
 * The daemon sets check_in_flight under its lock: even force requests join an
 * existing operation. Metadata/display and previous failure reason are daemon
 * state; record caches result without overwriting last success on errors. */
void d2ku_cache_observe(d2ku_status *, const d2ku_clock_sample *);
d2ku_rc d2ku_cache_record(d2ku_status *, const d2ku_clock_sample *, d2ku_rc);
int d2ku_check_due(const d2ku_status *, uint64_t mono_ms, int force);
typedef struct {
    unsigned char public_key[32];
    int64_t not_before, not_after; /* inclusive start, exclusive end */
} d2ku_key;
#define D2KU_SNAPSHOT_PATHS_MAX 16u
typedef struct {
    char name[D2KU_ID_MAX + 1]; /* one personal top-level entry, no symlinks */
    int configuration; /* 1 copied under lock before stop, 0 after stop */
} d2ku_snapshot_path;
typedef struct {
    void *arg;
    d2ku_rc (*capture)(void *, uint64_t *enabled);
    d2ku_rc (*services)(void *, const char *action, const char *release, uint64_t enabled);
    /* Optional test/platform seams; NULL uses production implementations. */
    d2ku_rc (*offline)(void *, int release_fd, const char *release);
    d2ku_rc (*updater_probe)(void *, const char *action, const char *release);
    d2ku_rc (*wait_ms)(void *, unsigned ms);
    d2ku_rc (*available_bytes)(void *, uint64_t *); /* NULL: root fstatvfs */
    int (*process_group)(void *, pid_t, pid_t); /* NULL: POSIX setpgid */
    d2ku_snapshot_path paths[D2KU_SNAPSHOT_PATHS_MAX];
    size_t path_count;
} d2ku_transaction_ops;
typedef struct {
    d2ku_ctx *ctx;
    char root[1024], runtime[1024], state[1024], identity[1024];
    char panel_host[128];
    uint64_t enabled;
    int identity_required;
} d2ku_service_config;
d2ku_rc d2ku_service_lock_valid(d2ku_ctx *, int);
d2ku_rc d2ku_service_configure(d2ku_ctx *, const char *, d2ku_service_config *);
d2ku_rc d2ku_service_capture(void *, uint64_t *);
d2ku_rc d2ku_service_call(void *, const char *, const char *, uint64_t);
d2ku_rc d2ku_service_dispatch(d2ku_service_config *, const char *, const char *, uint64_t);
d2ku_rc d2ku_service_health_state(void *);
d2ku_rc d2ku_service_health_rules(void *);
d2ku_rc d2ku_service_health_http(void *);
d2ku_rc d2ku_bootstrap(d2ku_ctx *, d2ku_status *);
struct d2ku_ctx {
    d2ku_transaction_ops transaction;
    int bootstrap_prefix_fd, bootstrap_bundle_fd; /* explicit installer-only directory handles */
    int maintenance_lock_fd; /* internal, valid only during transaction callbacks */
    int boot_control_fd; /* task9: inherited FD5; <=2 means standalone */
    /* Local health adapters: callbacks are read-only and cannot infer success
     * from PID alone. Absent callbacks use Linux proc, dirfd-relative state,
     * loopback HTTP and read-only iptables-save. runtime_dirfd must be supplied
     * for default health records (volatile /tmp/d2k). root holds releases/ID.
     * Fixed release binaries: d2kd,d2kc,d2kpanel,d2ktg. */
    void *health_arg;
    d2ku_rc (*health_observe)(void *, unsigned, const d2ku_journal *, d2ku_health_observation *);
    d2ku_rc (*health_state)(void *);
    d2ku_rc (*health_http)(void *);
    /* Probes ALL enabled own rules. Mandatory for Telegram-enabled health:
     * task6/7 service adapter owns real NAT/ipset/filter checks; absent fails
     * closed. Generic datapath default checks configured mangle expectations. */
    d2ku_rc (*health_rules)(void *);
    int health_runtime_dirfd;
    uint16_t health_panel_port; /* zero: 8090 */
    uint16_t health_queue; /* exact expected NFQUEUE number; zero is valid */
    int health_ipv6_rules;
    /* Full expected own-rule lines from the service adapter's configured
     * iptables-save representation; missing expectations fail closed.
     * IPv6 requirements have family=6, IPv4=4. No request-provided commands. */
    char health_rule_lines[32][512];
    unsigned char health_rule_family[32];
    size_t health_rule_count;
    char health_state_paths[8][D2KU_PATH_MAX + 1];
    size_t health_state_count; /* required when core/Telegram enabled */
    int root_dirfd; /* production: verified /opt/d2k dirfd */
    d2ku_clock clock;
    /* Bootstrap-owned HTTPS policy, never supplied by HTTP requests. */
    char transport_hosts[D2KU_HOSTS_MAX][D2KU_HOST_MAX + 1];
    size_t transport_host_count;
    char ca_bundle[D2KU_CA_PATH_MAX + 1]; /* installed system trust bundle */
    int staging_dirfd; /* caller-created private empty directory, not active */
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
    /* Optional POSIX write adapter: partial writes/EINTR allowed; -1 sets errno. */
    ssize_t (*write_fd)(void *arg, int fd, const void *bytes, size_t len);
    /* Optional POSIX fstat adapter: 0 on success; -1 sets errno. */
    int (*stat_fd)(void *arg, int fd, struct stat *out);
    d2ku_rc (*rename_at)(void *arg, int from_dirfd, const char *from,
        int to_dirfd, const char *to);
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
/* out_fd must be a private empty regular file at offset zero. Failure removes
 * partial download bytes. Only HTTPS to bootstrap hosts, including redirects. */
d2ku_rc d2ku_fetch(d2ku_ctx *, const char *url, int out_fd, uint64_t max_bytes);
/* chosen must be a fresh successfully verified index selected for this operation.
 * Bind exact bytes and release ID before exposing even incompatible metadata. */
d2ku_rc d2ku_verify_selected_manifest(d2ku_ctx *, const d2ku_index *chosen,
    const void *, size_t, const unsigned char sig[64], d2ku_manifest *);
/* Caller MUST have obtained manifest with verification result OK. Extract only
 * selected ABI's signed file list into ctx.staging_dirfd. No install/activation;
 * success means hash/size checks + file and directory fsync completed. */
d2ku_rc d2ku_stage(d2ku_ctx *, const d2ku_manifest *, int archive_fd);
/* Durable record schema 1. sequence is the storage generation, not a release
 * publication sequence. First store is 1, then increment exactly once/event.
 * Loading ABSENT/RECOVERY/IO leaves output unchanged. RECOVERY means existing
 * generations have no valid record: do not start a new release. */
typedef enum { D2KU_CHECKING = 1, D2KU_AVAILABLE, D2KU_DOWNLOADING,
    D2KU_VERIFYING, D2KU_PREPARED, D2KU_STOPPING, D2KU_SWITCHING,
    D2KU_STARTING, D2KU_VALIDATING, D2KU_COMMITTED, D2KU_ROLLING_BACK,
    D2KU_ROLLED_BACK, D2KU_RECOVERY_FAILED } d2ku_phase;
struct d2ku_journal {
    uint32_t schema;
    uint64_t sequence;
    unsigned char checksum[32]; /* computed on store, supplied by load */
    char transaction_id[D2KU_ID_MAX + 1]; size_t transaction_id_len;
    d2ku_phase phase;
    d2ku_rc failure_reason, recovery_reason; /* original cause and recovery failure */
    char old_release_id[D2KU_ID_MAX + 1]; size_t old_release_id_len;
    char new_release_id[D2KU_ID_MAX + 1]; size_t new_release_id_len;
    unsigned char old_manifest_sha256[32], new_manifest_sha256[32];
    int snapshot_ready;
    uint64_t active_services; /* caller's stable service bit mapping */
    uint64_t progress_mono_ms;
    int64_t progress_utc;
    char progress_boot_id[D2KU_BOOT_ID_MAX + 1]; size_t progress_boot_id_len;
};
typedef struct {
    uint32_t schema;
    uint64_t sequence;
    unsigned char checksum[32];
    uint64_t accepted_sequence;
    unsigned char accepted_index_sha256[32];
    int has_accepted_index;
    int64_t last_accepted_timestamp;
    d2ku_key trust[D2KU_KEYS_MAX]; size_t trust_count;
    d2ku_policy policy;
} d2ku_persistent_state;
d2ku_rc d2ku_journal_load(d2ku_ctx *, d2ku_journal *);
d2ku_rc d2ku_journal_store(d2ku_ctx *, const d2ku_journal *);
/* Independent trust/policy records: never copy/restore with runtime snapshots.
 * Apply to live context/policy only after successful durable store; load before
 * signature verification. Accepted sequence/time, trust and date floors cannot
 * decrease. Equal generation retries must have exactly identical payload. */
d2ku_rc d2ku_persistent_load(d2ku_ctx *, d2ku_persistent_state *);
d2ku_rc d2ku_persistent_store(d2ku_ctx *, const d2ku_persistent_state *);
/* Global maintenance lock shared by update and all service/config/hooks.
 * Descriptor is CLOEXEC; keep it for the whole transaction, close to unlock.
 * Stores also serialize on private record locks (safe while maintenance held).
 * No unlink of lock files: kernel releases lock on exit/crash. */
d2ku_rc d2ku_maintenance_lock(d2ku_ctx *, int *lock_fd);
void d2ku_maintenance_unlock(int lock_fd);
/* Poll at <=10s intervals under transaction lock. OK is instantaneous local
 * health only; durable commit requires status.health_complete. A failed probe,
 * process restart, boot/operation change or missed poll resets observation.
 * External availability is separate and never drives rollback. */
d2ku_rc d2ku_health(d2ku_ctx *, const d2ku_journal *, d2ku_status *);
/* Internal authenticated request, never deserialize these pointers from HTTP.
 * index/manifest must have passed verification OK and durable acceptance.
 * archive is rehashed by stage. Expected current binding is checked under lock.
 * Rollback uses only transaction_id and selected/expected bindings; archive=-1. */
struct d2ku_request {
    char transaction_id[D2KU_ID_MAX + 1];
    char expected_release_id[D2KU_ID_MAX + 1];
    unsigned char expected_manifest_sha256[32];
    char release_id[D2KU_ID_MAX + 1];
    unsigned char manifest_sha256[32];
    const d2ku_index *index;
    const d2ku_manifest *manifest;
    int archive_fd;
    int automatic;
};
d2ku_rc d2ku_install(d2ku_ctx *, const d2ku_request *, d2ku_status *);
d2ku_rc d2ku_rollback(d2ku_ctx *, const d2ku_request *, d2ku_status *);
d2ku_rc d2ku_recover(d2ku_ctx *, d2ku_status *);
/* Bootstrap receipt, used only after bootstrap verifies its inventory. */
d2ku_rc d2ku_release_receipt(d2ku_ctx *, const char *id, const unsigned char hash[32]);
/* Stable boot-v1 supervisor; owns child process group, kills/reaps before recover.
 * argv is local trusted CLI data. Heartbeat pipe is inherited as descriptor 3. */
d2ku_rc d2ku_supervise(d2ku_ctx *, const char *worker, char *const argv[], d2ku_status *);
/* Worker calls pulse at least once/second from an independent thread, even
 * during network I/O. fd must be inherited boot-v1 pipe, never persistent disk. */
d2ku_rc d2ku_boot_pulse(int fd, int ready);
#endif
