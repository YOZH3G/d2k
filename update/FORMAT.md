# D2K release metadata v1

This is the wire contract for `docs/auto-update-design.md` §3–4. Runtime is C,
OpenSSL EVP verifies Ed25519, and SHA-256 binds documents and artifacts.
Detached signatures are exactly 64 raw bytes, public keys exactly 32 bytes.
Signatures cover the original complete JSON byte sequence, including whitespace;
there is no JSON canonicalization before verification. TLS, transport host policy,
package unpacking and durable storage are separate modules.

## JSON rules and limits

Documents are UTF-8 JSON objects, schema `1`. Every field below is required
unless marked optional. Field order and JSON whitespace are insignificant to
parsing but significant to signatures and document hashes. Unknown fields,
duplicate keys (including escaped equivalents), trailing bytes other than JSON
whitespace, BOM, malformed UTF-8, invalid surrogate pairs and NUL are rejected.
Integer fields use JSON unsigned decimal integer syntax only: no sign, leading
zeros, exponent or fraction; range 0..18446744073709551615. Times are UTC epoch
seconds in 0..9223372036854775807. Strings decode JSON escapes before validation
and all string limits count decoded UTF-8 bytes, excluding the C terminator.

Index: ≤65536 bytes. Manifest: ≤1048576 bytes. Parser: depth ≤16 and ≤16384
value/key tokens. These bounds cover the v1 maximal known schema; unknown
extensions require a new implementation, not remote format replacement.

IDs: 1..64 ASCII bytes, first character alphanumeric; remainder alphanumeric,
`.` `_` or `-`. Display version: 1..64 UTF-8 bytes. Notes: 0..16384 UTF-8 bytes.
Commit: exactly 40 lowercase hexadecimal bytes. SHA-256 and public key fields:
exactly 64 lowercase hexadecimal bytes, decoded into 32-byte public arrays.

Relative paths/artifact names: 1..240 ASCII bytes, each component contains only
alphanumeric, `.` `_` or `-`; no absolute path, empty component, `.`, `..`, trailing
slash, backslash or control character. They are data for dirfd-relative operations,
never shell command text. Metadata validation does not replace extraction checks.

## Index

| Field | Type / meaning |
| --- | --- |
| `schema` | integer, exactly 1 |
| `channel` | string, exactly `stable` |
| `sequence` | positive uint64 monotonic publication number |
| `issued_at` | UTC time, ≤ trustworthy current time |
| `expires_at` | UTC time, > `issued_at` and > current time |
| `release_id` | release ID |
| `manifest_sha256` | SHA-256 of the exact signed manifest bytes |

The channel pointer and its detached signature are published after all immutable
release artifacts. Storage layout/HTTPS locations belong to transport and release
tooling; no arbitrary URL exists in this format.

`d2ku_verify_index` returns `document_sha256`, computed over authenticated original
bytes. Sequence below `ctx.accepted_sequence` is REPLAY. Equal sequence is OK only
if `ctx.has_accepted_index` and the document hash equals the durable accepted hash;
it is REPLAY otherwise, even if semantics differ only in whitespace. Higher
sequence is verified but not automatically persisted. Repeated checks of an
identical index remain subject to expiry and current signing-key validity.

## Manifest

| Field | Type / meaning |
| --- | --- |
| `schema` | integer, exactly 1 |
| `release_id` | release ID, must match chosen index in transport |
| `version` | display version |
| `commit` | clean source revision, 40 lowercase hex bytes |
| `built_at` | UTC time, ≤ trustworthy current time |
| `notes` | release notes; render as text, never trusted HTML |
| `min_updater` | positive integer updater protocol version |
| `wire` | positive integer common runtime wire version |
| `state` | positive integer bidirectionally compatible persistent-state version |
| `packages` | nonempty array, ≤9 ABI package objects |
| `signing_keys` | optional nonempty array, ≤8 trust transition objects |

v1 installation requires `min_updater <= ctx.updater_version`,
`wire == ctx.wire_version`, `state == ctx.state_version`, and a package for
`ctx.abi`. The state equality deliberately excludes any incompatible migration.

Each package has exactly these fields:

| Field | Type / meaning |
| --- | --- |
| `abi` | one of `arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64` |
| `artifact` | relative storage name of uncompressed ustar package |
| `size` | positive uint64 exact artifact byte count |
| `sha256` | SHA-256 of complete artifact bytes |
| `files` | nonempty array of regular-file objects |

ABIs and artifact names are unique across packages. The whole manifest has ≤512
file entries across all packages. Public representation uses one flat bounded
`files[]` array and each package's `file_offset` / `file_count` range. Identical
paths across different ABI packages are allowed; within one package no duplicate
or file/parent path conflict is allowed.

Each file has exactly `path` (relative path), `size` (uint64, zero allowed),
`mode` (integer 420 = 0644 or 493 = 0755), and `sha256` (full regular-file bytes).
Total regular-file payload size must not exceed package size, checked without
integer overflow. Exact ustar overhead and whole-file hash are checked by the
package module. Parent directories are implied by listed regular files; unpacking
may admit only those directories, ordinary listed files, and no links/devices or
unknown tar header extensions. The release-owned file allowlist is independent
and must exclude config, secrets, knowledge, logs, and registration state.

## Signing keys and trust transitions

A transition object has exactly `public_key`, `not_before`, `not_after`.
Validity is `[not_before, not_after)`, with `not_before < not_after`; the proposed
key must remain valid after current time and its interval must overlap the
verified old signer's interval. Future activation is allowed during overlap.
Duplicate proposed keys are rejected. An existing trusted key may be restated
only with exactly its existing validity interval; this is idempotent replay,
not an unsigned extension of an expired key. Current plus newly proposed keys
must fit the bound of eight; retiring expired keys is a later durable trust
policy, never an implicit runtime-rollback action.

Verification tries only `ctx.trust[]`, before any semantic JSON parsing; an
untrusted manifest cannot select or introduce the key that verifies itself.
A cryptographically matching key outside its validity interval returns EXPIRED.
Trustworthy UTC from `ctx.clock.wall` is mandatory (TIME otherwise). Bootstrap
provides the initial pinned public key and validity interval. No production key
is supplied by these tests or embedded in this module.

Manifest verification exposes transitions and the trusted `signing_key_index`
but never mutates context or activates a key. The transition release must be
accepted through the old trust chain, with durable persistence before new keys
can be used. Key removal, root trust replacement and bootstrap-format replacement
are not expressible in this v1 manifest.

## API and durable integration obligations

Both verification functions return bounded, fully owned output with explicit
string/array lengths; no pointer references the input or private allocations.
Unknown schema returns INCOMPATIBLE and leaves output unchanged. INVALID,
UNTRUSTED, EXPIRED, REPLAY, TIME and IO leave output unchanged. Index output is
populated only on OK. For a fully authenticated and structurally validated
schema=1 manifest with ABI/updater/wire/state mismatch, INCOMPATIBLE populates
output for version/notes display. Installation and activation of transition keys
must require OK. A malformed
incompatible manifest never exposes partial metadata. Context is never mutated.

The caller must bind index release ID + manifest SHA-256 to the received original
manifest bytes and bind the operation's selected release ID/hash; a valid
signature alone does not establish that linkage. A manifest has no independent
expiry: selection always uses a fresh accepted index, current trust and current
compatibility context.

Acceptance is separate from runtime rollback. Before exposing a candidate as
accepted or using returned transition keys, the durable trust module must write
and fsync the accepted sequence, exact index hash and approved trust state,
atomically publish that state and fsync its parent directory. On failure it must
retain the old authoritative trust state and must not activate proposed keys.
These records live outside release snapshots; runtime rollback never decreases
the publication number or restores old trust. Reboot loads this durable context
before checking signatures. Disk I/O and service callbacks in `d2ku_ctx` are
caller-owned seams for later isolated transaction tests; verification performs
no file, network or service action.

## HTTPS and staging API

Bootstrap supplies `ctx.transport_hosts` (1..8 exact DNS hostnames) and
`ctx.ca_bundle` (an installed, readable system CA bundle). Neither is HTTP input.
`d2ku_fetch` requires a caller-owned private empty regular file, one link, a
writable non-append descriptor at offset zero. It permits only HTTPS, checks the
hostname and chain, disables environment proxies and content decompression,
limits streamed bytes to the caller's metadata/package bound, uses a 15-second
connect timeout and a 30-second low-speed timeout, and follows at most five
redirects after checking each resolved HTTPS host against bootstrap policy.
Credentials and fragments are rejected. A failed transfer truncates its own
partial output; an invalid pre-existing destination is left untouched. Missing
or unusable CA trust fails UNTRUSTED, with no insecure fallback. HTTP success is
exactly 200; redirect/error bodies never become the output artifact.

After fetching manifest bytes and their detached signature, the caller passes
the operation's fresh successfully verified chosen index into
`d2ku_verify_selected_manifest`. This checks the exact original-byte SHA-256,
signature and release ID before exposing metadata. A different signed release
cannot replace the selected one. INCOMPATIBLE remains authenticated display-only
metadata; installation requires OK. This helper neither refreshes latest nor
accepts/persists an index.

`d2ku_stage` consumes only a manifest previously verified with result OK by the
trusted C caller. C structs are an internal API, never an HTTP input. It repeats
schema/range/compatibility checks and selects exactly `ctx.abi`'s flat file range.
The caller opens a new private directory in `ctx.staging_dirfd`, owned by the
updater UID (root in production) with no group/world access. The function rejects
any existing directory entry, including symlinks, without deleting it. The
release tooling's independent runtime-owned allowlist excludes personal data;
staging enforces the signed package's exact file list.

Only POSIX ustar (`ustar\0`, version `00`) is accepted: regular files and distinct
implied parent directories, octal fields, correct unsigned checksum, exact file
sizes and modes, no link/device/extension headers, zero payload padding, at least
two zero end blocks and only zero archive padding. Prefix/name joins are checked
against the same relative-path grammar. Each signed file occurs exactly once;
only directories implied by those files may occur. Ownership from tar is ignored;
files belong to the updater UID. Directory modes are 0700/0755, output directories
0755 beneath the private staging container; file modes are exactly 0644/0755.

The exact regular archive size and SHA-256 are checked before writing, each
file's SHA-256 while streaming, and the archive hash/size again before success.
Creation uses dirfd-relative openat/mkdirat, O_NOFOLLOW and O_EXCL. File bytes
are bounded by signed sizes. All files are fsynced after their final modes;
implied directories are fsynced bottom-up, then the staging directory is fsynced.
On error only this attempt's created filenames/directories are removed. The
function never installs a release, writes active/config/state, executes scripts,
or emits a durable prepared transaction. The transaction layer owns durable
creation/removal of the staging container (including its parent fsync) and the
prepared journal transition after staging returns OK.

## Clock, schedule, cache and quarantine policy

`schedule.c` performs policy only, with no file, network or service operations.
The daemon supplies `clock.snapshot` through a platform adapter using the same
clock as `clock.wall` and `clock.monotonic`. A snapshot owns its bounded boot ID
and router timezone, UTC seconds, monotonic milliseconds, local Gregorian date
(`YYYYMMDD`) and minute of day. The adapter derives the local fields from that
captured UTC in the router's current timezone, including its POSIX `TZ` setting;
it must not use the development host timezone or invent a default timezone.
Boot ID is an opaque stable identifier for this boot; missing identity fails
closed. Milliseconds in policy are distinct from the legacy monotonic callback's
nanoseconds. The daemon's real adapter is separately verified during field
preflight; fake clock unit tests are not evidence of platform synchronization.

`synchronized == 1` means the platform positively confirmed clock synchronization;
unknown or unsynchronized status is not trusted. `d2ku_read_clock` also requires
valid calendar/boot/timezone fields and UTC at or after BOTH `build_timestamp`
and the durable `last_accepted_timestamp`. No year threshold substitutes for
confirmed synchronization. `clock.wall`, used by signature verification, must
enforce the same gate. `D2KU_TIME` blocks automatic AND manual installation and
signature freshness checks. Failed reads leave the output unchanged. Observing
or caching an error requires only a valid boot ID, and does not bypass this gate.
The daemon advances the accepted UTC floor durably as a high-water mark; reboot
and release rollback never reduce it. It supplies the installed build timestamp
from trusted build metadata, not a value supplied by a panel request.

The daemon supplies an unbiased random integer 0..119 to `d2ku_select_minute`.
The selected minute is `180 + offset`, representing `[03:00, 05:00)`. The selected
date/minute must be durably saved before use, and repeated selection on that date
keeps the saved minute. Dates below either saved selection or last auto-attempt
date are rejected with TIME. This durable high-water rule conservatively delays
installation after a backward date/timezone change until the date advances.

`d2ku_auto_due` is ONLY the schedule predicate: enabled, saved selection for the
current local date, current minute at/after that selection and before 05:00,
and date strictly greater than the durable last auto-attempt date. Boot after
the selected minute may catch up before 05:00; repeated hours, clock rollback
and reboot do not reset the date guard. A skipped minute due to DST permits the
same catch-up within the window; a skipped whole window never permits daytime
installation. Automatic installation additionally requires
`d2ku_auto_release_allowed` for the exact chosen manifest SHA-256, successfully
verified compatible metadata, and the transaction layer's other preconditions.

After downloading/staging, the caller rechecks the schedule and quarantine
immediately before beginning installation. `d2ku_mark_auto_attempt` updates the
in-memory date only if the schedule is still due (BUSY otherwise, TIME for
untrusted time). Caller locking must serialize this claim, and the journal/daemon
must durably fsync the new date BEFORE beginning the automatic transaction.
Persistence failure means no installation. A download finishing at/after 05:00
does not consume an installation attempt: the prepared release waits for the
next window. Already begun switch, validation or rollback runs to completion
after 05:00. Manual installation does not call this auto-attempt marker.

The quarantined release hash is durable local policy, outside release rollback.
Automatic installation of that exact manifest hash is forbidden on later nights;
a different hash is not quarantined by this record. Manual retry is a distinct,
explicit daemon action showing the stored failure reason; it bypasses only the
automatic quarantine guard, never clock/signature/compatibility checks.

The check cache is volatile and shared by all device clients. The daemon calls
`d2ku_cache_observe` before `d2ku_check_due`; changed/unknown boot identity or a
backward monotonic reading requires a new check, even when numeric milliseconds
match the old boot. The TTL is exactly 900000 ms: age 899 seconds is cached,
900 seconds is due. `d2ku_cache_record` stores the latest check result, including
errors, with that same TTL; errors retain the timestamp of the last successful
check. The daemon retains its authenticated metadata separately and must not
present stale metadata as a fresh successful result after failure.

Force requests bypass a cached result, but `check_in_flight` takes precedence:
callers join the current operation. The daemon sets/clears this flag and checks
the predicate under its operation lock; policy alone provides no synchronization.
Disabling automatic installation never disables `d2ku_check_due`, manual actions,
or the daemon's nightly check request. The daemon uses the saved date/minute for
nightly checking independently of `enabled`; `auto_due` gates installation only.
Opening the panel starts only a due check; it never calls install/stage, nor
requests a package download.

## Durable records and maintenance locking (schema 1)

Journal and security/schedule state are **independent** records beneath the
verified `/opt/d2k` root dirfd, in the updater-owned `update-state/` directory
(mode 0700). Record/lock files are regular, single-link, updater-owned, mode
0600; symlinks and group/world access are rejected. Paths are fixed C constants,
not metadata or request strings. Runtime snapshots/rollback must exclude this
whole directory. The directory's root parent is synchronized before stores.

Two generations per type are `journal.0`, `journal.1` and `persistent.0`,
`persistent.1`. Slot is storage sequence modulo two. The **storage sequence** is
independent of the index's publication sequence. First store is sequence 1;
subsequent stores increment exactly once for a phase or significant event.
Status polls and download chunks do not write. Sequence overflow is refused.
`load` validates both files and selects the greatest valid sequence. A torn or
malformed newest generation falls back to the valid older one. Both absent is
`D2KU_ABSENT` (bootstrap must decide initialization); any existing records with
no valid generation give `D2KU_RECOVERY`. Read/access errors give `D2KU_IO` even
if the other generation is valid. These failures leave caller output unchanged
and never authorize launching a new release. Corrupt records are preserved.

The format is binary, all unsigned integers big endian, with **no raw C struct
bytes, padding, pointers, size_t or enum representation**. All strings are a
u16 byte length followed by exactly that many bytes, without terminator. Header:

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `D2KJNL01` or `D2KPER01` |
| 8 | 4 | schema u32, exactly 1 |
| 12 | 4 | total record byte length u32, at most 4096 |
| 16 | 8 | positive storage sequence u64 |
| 24 | 32 | SHA-256 over entire record with these 32 bytes zeroed |
| 56 | variable | exactly the payload below; no trailing bytes |

Checksum binds type, schema, length, generation and payload. It detects damage,
not malicious modifications by privileged writers; signed metadata acceptance
remains the trust boundary. Schema/type, sequence/slot consistency, exact length,
checksum, every scalar range and string grammar are validated before exposure.
Unsupported/corrupt generations are never decoded by guessed struct layout.

Journal payload, in order: transaction ID string; phase u32; original failure
reason u32; recovery failure reason u32; old release ID
string; new release ID string; old and new exact manifest SHA-256 (32 bytes
each); snapshot-ready u8 boolean; active services u64 bitset; monotonic progress
milliseconds u64; UTC progress seconds u64 (0..INT64_MAX); progress boot ID
string. IDs use the release-ID grammar and 64-byte bound; boot ID is 1..64
printable non-space ASCII bytes. Both reasons are explicit d2ku_rc values
0..12 (OK through RECOVERY); zero means no failure. The first transaction
cause survives a successful rollback; recovery_reason records failure of
recovery independently. These two fields were added before the first release
of schema 1: no deployed record migration is implied. Phases 1..13 are checking, available,
downloading, verifying, prepared, stopping, switching, starting, validating,
committed, rolling_back, rolled_back, recovery_failed. Switching through
committed requires snapshot-ready=1. The caller defines a stable service bit
mapping, binds operation/old/new identities to actual validated releases, and
owns legal phase transitions. A checksum does not prove that a snapshot exists
or that a service is healthy. Boot ID makes a saved monotonic heartbeat usable
only in its original boot; task 6/7 must handle a different boot conservatively.

Persistent payload, in order: accepted publication sequence u64; exact accepted
index SHA-256 (32 bytes); has-accepted-index u8 boolean; trusted accepted-time
floor u64 (0..INT64_MAX); trust-key count u8 (1..8); for each key public bytes
(32), not-before u64 and not-after u64 (0..INT64_MAX, increasing, no duplicates);
policy enabled u8; selected local YYYYMMDD u32; last-attempt local YYYYMMDD u32;
selected local minute u16; has-quarantined-release u8; exact quarantined manifest
SHA-256 (32 bytes). Dates are zero/unselected or valid Gregorian dates
19700101..99991231. Selected minute is zero when unselected, otherwise 180..299.
Accepted sequence is positive exactly when has-accepted-index=1. Trust keys are
public, with no private material. Store refuses decreasing publication/time/date
floors, changing digest at equal accepted publication, changing the selected
minute for an existing date, removing existing keys or altering their intervals.
Adding keys must already have been authorized by the signature verifier; these
persistence APIs do not authenticate arbitrary input. Key retirement is outside
v1. Runtime rollback or journal deletion never rewinds this state. Reload it
before signature verification, and update live ctx/policy only after store OK.

Stores serialize using private `journal.lock`/`persistent.lock` files. Each
store creates a unique own temporary with O_EXCL, fully writes (handling short
writes and EINTR), fsyncs its fd, closes, renames to the next slot, then fsyncs
`update-state/`. All errors prevent success; only the exact temporary created
by the current call is removed. No stale/foreign-temp sweep exists. Crash-left
temporaries are ignored by readers. The previous slot is untouched by publication.
Optional caller-owned `write_fd`, `stat_fd`, `sync_fd`, `rename_at` callbacks exercise I/O
faults; absent callbacks use real POSIX calls. sync_fd applies to files and dirs.

**An error after rename has an ambiguous durability outcome.** The new generation
may be visible even after parent fsync fails, and may or may not survive a power
loss. Store returns IO and the running caller must not report durable commit or
activate new trust/policy on that result. A retry with identical generation and
payload re-fsyncs the visible inode and directory; equal generation with changed
payload is REPLAY. Recovery uses the validated generation it actually observes,
including a possibly visible terminal phase; it cannot infer an old generation
from an earlier API error. Task 6 must reconcile recorded release identities and
phase with actual `current`/snapshot/services and durably journal any rollback
before declaring it complete. A failed terminal store is not permission to
ignore a visible terminal record or blindly launch/revert a release. True storage
loss remains outside software recovery guarantees, as in design §6.

`d2ku_maintenance_lock` opens `maintenance.lock` with CLOEXEC and takes nonblocking
exclusive flock. Every service/config/watchdog/NDM entry must use this same lock;
update holds its returned fd across the transaction and invokes internal service
commands without reacquisition. BUSY leaves output unchanged. Close releases the
lock; process exit/crash releases it through the kernel. Lock files are never
unlinked (avoiding split-inode locks). Record locks are distinct, allowing durable
writes while maintenance is held. These primitives do not stop/start services,
switch `current`, copy snapshots, enforce heartbeat health or perform rollback;
those responsibilities belong to the consuming transaction/recovery modules.


## Transaction and stable boot protocol v1

`d2ku_install` accepts an internal authenticated request: original verified
manifest, fresh durably accepted index, selected ID/hash, archive descriptor,
operation ID, and expected current ID/hash. These are C-side bindings; HTTP
must not create a manifest structure. Manual installation still applies the
trusted clock gate. Automatic installation additionally checks durable policy
and consumes its date under the maintenance lock immediately before preparing
the stop; the daemon must not consume that date a second time.

Preparation verifies/stages the exact archive, hashes the ABI file set again,
runs each of d2kd/d2kc/d2kpanel/d2ktg/d2k-update with `--release-id` and
`--self-check`, and requires updater `--boot-protocol` to print exactly `1\n`.
Each offline process has a five-second deadline and receives no live config
path. `releases/.stage-<operation>` is published by rename only after all files
and its private `.d2ku-receipt` are synced. Reuse of an existing ID requires
matching receipt and freshly matching signed file hashes, modes and sizes.
Stable `boot/` is outside every release. Receipt format is
`D2KR1 <wire> <state> <updater-version> <manifest-sha256-hex>\n`.
Bootstrap uses `d2ku_release_receipt` only after verifying its old inventory.

The transaction rechecks expected current, receipt, state compatibility and
actual filesystem space under the shared maintenance lock. Required callbacks
`transaction.capture` and `transaction.services` cannot default to success.
Capture returns the exact enabled bitset (1 datapath, 2 core, 4 panel, 8 TG).
Services receives fixed action `stop`, `start` or `remove-rules`, explicit
release ID and preserved bitset. Stop must reap every persistent writer,
flush state and remove only D2K rules; start must start only that bitset from
the single supplied release. Callbacks must not reacquire maintenance.
`ctx.maintenance_lock_fd` is valid only during these locked callbacks.

The adapter supplies 1..16 personal top-level snapshot entries and marks each
configuration or state. No slash, link, special file, duplicate, reserved
update-state/update/releases/boot/current/run/log(s)/staging/snapshots entry is
accepted. Configuration is copied before stopping under the lock. State is
inventoried anew and copied only after stop succeeds, including files first
created during shutdown. `snapshots/<operation>` is private root-owned storage,
separate from trust/policy; inventory records absent entries and a SHA-256 seal
binds names, types, modes and all bytes. Only full copy + seal + fsync makes
snapshot_ready durable. Recovery validates the whole seal before changing any
live entry. Copy+rename from the retained snapshot is restartable; interrupted
restore never consumes the source. An incomplete snapshot is ignored and the
old live state remains authoritative. Successful late rollback uses a new
snapshot of current compatible state and never reuses the old pre-install data.

`current` changes via a temporary relative symlink, rename and parent fsync.
The old worker continues running from its original inode through switching.
Candidate updater startup is checked separately before observation: execute
`releases/<ID>/d2k-update --boot-probe 3 --root-fd 4`, cwd its release directory.
FD3 is a nonblocking anonymous pipe; FD4 is a read-only root directory handle.
Task9 must initialize the real daemon/config/state readers, with schedulers,
transactions and mutations disabled; no public IPC socket is claimed. It must
emit `D2KU1 READY\n` only after initialization, then `D2KU1 PULSE\n` at least
once a second. It must exit when the pipe closes. No child processes may outlive
this probe. Linux additionally binds probe death to its parent with PDEATHSIG.
Missing readiness after 10 seconds, malformed records, exit, or 10 seconds
without heartbeat fail the candidate. The candidate remains alive through
COMMITTED publication; the transaction kills/reaps the probe afterwards.

Only after READY does continuous runtime observation begin. Every enabled
service is checked every second by `d2ku_health`; commit requires
health_complete after 120000 monotonic milliseconds, with the same process
identities. Restarts cannot extend the observation forever: failure to complete
within that observation window rolls back. External availability is separate.
The successful rollback also verifies the old runtime; no retry loop starts
once RECOVERY_FAILED is recorded. Failure to durably record quarantine likewise
fails recovery closed. Reason codes persist in the journal without secrets.

A failed terminal store may be visible. The running transaction reloads its
actual generation and writes explicit ROLLING_BACK before reverting. Recovery
of a visible terminal record reconciles the recorded ID/hash against actual
current/receipt; mismatch becomes RECOVERY_FAILED, never an assumed old state.
Normal startup after an already terminal transaction remains the boot service
adapter's responsibility. Incomplete transactions stop both possible writers,
restore only a ready verified snapshot, select old, restart the saved bitset,
and durably record ROLLED_BACK. RECOVERY_FAILED removes own interception via
the adapter and rejects subsequent automatic recovery attempts.

### Stable executable and Task7 adapter

Build `make -C update boot`: `d2k-update-boot` links transaction/journal/package/
health/schedule and OpenSSL, **no libcurl** and no candidate shared library.
Production installs it in stable bootstrap storage outside releases. Commands:

- `d2k-update-boot --boot-protocol` prints `1`.
- `d2k-update-boot --recover` reconciles before ordinary D2K startup.
- `d2k-update-boot --supervise /opt/d2k/current/d2k-update --boot-worker 3`
  supervises the daemon. The daemon uses inherited FD3 and `d2ku_boot_pulse`
  from an independent one-second heartbeat thread so downloads cannot block it.
  On exit or heartbeat loss, boot kills/reaps its owned worker group first,
  then obtains maintenance and independently recovers. It does not respawn a
  failed worker in a loop. Worker argv is trusted bootstrap CLI, never HTTP.
- Test/standalone CLI may precede the command with `--root DIR --runtime DIR`;
  defaults are `/opt/d2k` and `/tmp/d2k`. There is no HTTP root override.

Boot recovery executes only verified regular root-owned, non-writable-by-others
`boot/d2k-service-adapter`, a stable C adapter supplied by Task7. Exact argv:
`d2k-service-adapter --maintenance-fd 4 ACTION RELEASE SERVICE_BITS`.
FD4 is a duplicate of the parent's locked maintenance file description and
survives exec. Task7 must verify it belongs to its expected maintenance inode
and use the held lock rather than acquiring another. Before spawning any
long-lived runtime, close FD4 in that child or mark it CLOEXEC; a runtime must
never retain the maintenance lock. The cwd is `boot/`.
Fixed actions are `stop`, `start`, `remove-rules`, `health-state`,
`health-rules`, `health-http`; health actions receive `- 0` and derive the
actual configured enabled set from personal configuration. Exit 0 is success;
any other status/timeout (30 seconds) is failure. This is not a shell-string
interface. Missing adapter fails closed. Task7 must supply actual config/state,
loopback panel and ALL datapath/TG NAT/ipset/filter rule checks; these are not
claimed by callback fixtures. Boot uses Linux default executable/heartbeat
observations against the restored release and volatile runtime directory.
