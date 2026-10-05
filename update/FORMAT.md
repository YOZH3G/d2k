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

Before starting automatic package download (including a failed download),
`d2ku_auto_reserve` takes maintenance, checks trusted time/window/quarantine,
and durably stores the local attempt date plus operation ID, selected release ID
and manifest hash. A download failure or reboot does not refund the date.
`d2ku_auto_reservation_valid` rechecks this exact binding and the current window
under transaction maintenance before preparation/switch; an `automatic` flag
alone never bypasses the date guard. A package finishing at/after 05:00 remains
in the bounded prepared cache for a later window, which requires a new date's
validated reservation. Already begun switch/validation/recovery runs to
completion after 05:00. Manual installation never consumes the automatic date.

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
string; canonical request command u8, exactly 3 (install) or 4 (rollback);
old source kind u8, exactly 0 (runtime) or 1 (legacy-local-v1). Kind1 permits
install only. Target kind is always runtime; remote metadata cannot select legacy.
IDs use the release-ID grammar and 64-byte bound; boot ID is 1..64
printable non-space ASCII bytes. Both reasons are explicit d2ku_rc values
0..12 (OK through RECOVERY); zero means no failure. The first transaction
cause survives a successful rollback; recovery_reason records failure of
recovery independently. These two fields were added before the first release
of schema 1; the canonical command tail was also added before publication.
The old-kind tail is also a prepublication extension. No deployed record
migration is implied. Missing/unknown command or source-kind tails fail closed;
never infer install vs rollback from release IDs or terminal phase. Phases 1..13 are checking, available,
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
SHA-256 (32 bytes); auto-reservation operation ID and release ID (each the
existing length-prefixed bounded string encoding), then manifest SHA-256
(32 bytes); quarantine reason u32 (d2ku_rc 1..12 while quarantine is active,
exactly 0 otherwise). Hash and reason are stored in one atomic generation and
survive journal rotation. Empty reservation IDs mean no active reservation; populated fields
are bound to the last-attempt date. Dates are zero/unselected or valid Gregorian dates
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
and validates its already durable predownload reservation under the maintenance
lock before preparation. The transaction never consumes that date a second time.

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
  failed worker in a loop. Worker argv is trusted bootstrap CLI, never HTTP. FD5 ownership registration
  below is mandatory in the supervised worker context.
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


### Offline process ownership (boot v1, unreleased correction)

The bootstrap supervisor additionally inherits an anonymous nonblocking Unix
stream control socket as **FD5** into the worker. Task9 must set
`ctx.boot_control_fd = 5` before calling transaction APIs in `--boot-worker`
mode. Values <=2 select the standalone path, not supervised mode. Heartbeat FD3
is independent; the one-second heartbeat thread never shares the control stream.
Control requests are serialized by the transaction worker; no runtime/service
process may use or retain FD5. Offline executables and candidate startup probes
explicitly close the worker's FD3/FD5 handles (probe FD3 is its own new pipe).

Frames are exactly eight bytes: four ASCII tag bytes followed by a u32 positive
PID, big endian (2..INT32_MAX). Request `D2GR` registers an offline child;
`D2GU` unregisters it. Reply `D2GA` echoes the exact PID. No text/newline, shell
command, path or arbitrary action exists in these frames. Up to 16 outstanding
owned groups are accepted. Duplicate/unknown PID, wrong tag, invalid PID/group,
overflow or failed acknowledgement fails the operation closed. Worker request
and acknowledgement I/O is bounded to five seconds. On macOS the socket uses
SO_NOSIGPIPE; Linux sends suppress SIGPIPE.

The offline child starts **held behind a pipe gate**, still in the worker PGID,
with a Linux parent-death signal and a parent identity recheck. A closed gate
also aborts without exec; no descendants can exist while held. Supervisor accepts
registration only while that PID is in its worker's process group, remembers
ownership **before** acknowledgement, then replies. Only after receiving ACK may
the worker move the held child to PGID=child PID and release exec. Thus death
before registration leaves the held child in the already-owned worker group;
death after ACK leaves it either there or in a registered group. There is no
unowned executable interval.

On normal offline completion or its existing five-second self-check timeout,
the worker kills/reaps the direct child and requests unregister. Bootstrap kills
any remaining members and accepts unregister only once the complete group is
gone. Linux bootstrap is a child subreaper and waits only for its known worker
and registered PGIDs, including adopted descendants. On worker death it kills
and reaps these same groups **before** recovery; ordinary service groups are not
registered, enumerated or killed. Group cleanup has a five-second completion
bound; if killed writers cannot be confirmed gone, bootstrap returns RECOVERY
without touching persistent state. Standalone invocation retains bounded local
process-group kill/cleanup without the FD5 protocol.

### Terminal retry, snapshot framing, outstanding space

A visible COMMITTED/ROLLED_BACK record is insufficient for successful recovery:
a worker can die after record rename and before journal-directory fsync.
After reconciling current/receipt, recovery retries `d2ku_journal_store` with
exactly the observed generation and payload. The journal layer re-syncs the
visible record inode and parent; any failure propagates and the sequence is not
advanced. The regression cuts execution *before* the real terminal directory
fsync, rather than after a successful barrier.

Snapshot hashing encodes hierarchy. Each node begins with u16 permission bits,
then D/F type, then NUL-terminated basename. File nodes additionally prefix
content with its u64 big-endian length and retain the decimal `/length/` suffix.
Directory nodes contain sorted children followed by byte FF; this delimiter
cannot be the leading permission byte of a node. Moving a file beneath a
previously empty sibling directory therefore changes the seal. This framing is
fixed before initial production release of boot v1; no deployed snapshot
migration is implied.

Free-space checks charge only outstanding allocation. Before unpacking a new
release: selected ABI's signed file range plus personal snapshot/restore reserve.
Other ABI file ranges are excluded. If that release directory is already
prepared, and again under lock after preparation, only the remaining personal
snapshot/restore reserve is charged; current free space already reflects the
allocated release. `transaction.available_bytes` is an optional platform/test
seam; absent callback reads real root fstatvfs. Archive bytes are already present
in the authenticated request's archive descriptor before transaction staging.

## Flat bootstrap and service integration (Task 7)

`d2ku_bootstrap(ctx,status)` is installer-only. `bootstrap_prefix_fd` is a verified
`/opt` directory and `bootstrap_bundle_fd` is an explicitly verified local bundle;
it is not an HTTP parameter or unsigned download mechanism. Standalone command:
`d2k-update-boot [--root DIR] --bootstrap BUNDLE`. The bundle contains executable
`d2k-update-boot`, `d2k-service-adapter`, `S98d2k-update`, `S99d2k`, `001-d2k.sh`,
`uninstall.sh` and the seven installed `d2k-*.sh` helpers. Release tooling must
stage executable modes before handing this directory to bootstrap. Bundle
publication/trust distribution remains the release/bootstrap packaging task.

Ordinary flat inventory checks all four binaries using bounded offline self-checks,
requires wire13 and one common embedded release identity. The prepared
`voice-4faa482` bundle retains that exact identity and ordinary health contract.
Historical field wire12 instead uses the separate local-owner contract below.
Neither old source is represented as a newly signed publisher release. Both
paths reject missing, linked, foreign-owned or writable-by-other inventory
before stop. `update/legacy-flat/` retains original binaries, init/NDM, helpers
and assets; ordinary wire13 also saves flat config there. Legacy wire12 excludes
personal config from its immutable code seal. `boot/input/` retains validated
bootstrap inputs so interruption never depends on installer temporary files.

`update-state/bootstrap.pending` is the durable forward-completion record:
`D2KB2 SOURCE_KIND ID OLD_SEAL INPUT_SEAL SERVICE_BITS CHECKSUM\n`. Seals/checksum are 64 lower
hex bytes; SOURCE_KIND is canonical decimal0 or1; checksum is SHA256 of the exact preceding bytes excluding the space
before CHECKSUM. The whole record is canonical, private, bounded, type checked
and verified before use. The independent C executable and S98 recovery hook are
synced before this record and before replacing any entry. Init/NDM/helper guards
are replaced before stop/switch; outside operations wait on maintenance. For ordinary wire13, services
stop with the saved mask, personal snapshot entries are retained under
`update/legacy-personal/` after writers stop, current and launchers are published,
and only the saved service mask starts. Live personal files are never rewritten
by migration. Completion renames pending to `bootstrap.done` and syncs the parent.
Recovery resumes from the sealed saved trees; it never recopies overwritten flat
entry points as the original inventory. A failure before pending leaves the flat
installation authoritative. Neither uncertain fsync nor a failed start is success.

Stable `/opt/sbin/d2k*` launchers resolve current once through the C adapter.
Binary aliases accept offline metadata/self-check and bounded read-only TG probe
commands. Direct daemon launches are refused: managed writers must enter through
service commands so a process cannot start after releasing maintenance and evade
an in-progress state snapshot. Init starts explicit release binaries internally.
`boot/d2k-service-adapter service ACTION` serializes supported lifecycle actions;
Task9's `d2k-update service ACTION` must forward to this stable entry, including
configuration changes. The legacy installer detects managed markers before any
fetch/module action and routes to `service install`. Bare install fails nonzero
with explicit not-installed/selection guidance. `service check` forwards a force
check; `service install ID HASH` forwards that exact selection to authenticated
IPC before acquiring maintenance (the daemon owns transaction locking). Neither
command substitutes latest or falls back to unsigned installation.
S98 runs recovery synchronously and starts the independent supervisor in the
background when current supplies `d2k-update` or a bootstrap first worker exists.
Stable boot validates first-worker eligibility before executing it. The worker
implements `--boot-worker 3`, independent heartbeat and FD5 protocol specified
above. Normal D2K stop does not stop that supervisor.

Internal contract remains `--maintenance-fd 4 ACTION RELEASE SERVICE_BITS`.
The adapter validates ownership/type/inode against maintenance.lock, verifies a
separately opened description cannot acquire it, and on Linux requires FD4's own
FLOCK/WRITE fdinfo record. It never reacquires FD4. Service callbacks run with a
30-second deadline in acknowledged FD5 transient process groups; runtime children
close FDs3/4/5 before start-stop-daemon and never inherit internal authority.
Shell init/helper scripts remain fixed validated platform adapters; new lifecycle
orchestration is C. All external NDM, firewall/PPE, Telegram, DNS and log helper
mutations route to the shared maintenance entry. Scheduler loops lock individual
operations, so an idle long-lived helper does not own maintenance indefinitely.

`d2ku_service_configure` supplies wire13, real queue/listen address, numeric IPv4/
IPv6 HTTP target, state paths and transaction callbacks. Boot creates/verifies
the actual configured private volatile directory and opens health_runtime_dirfd.
Task9 must do the same using the returned runtime path. Core's existing catalog
is `state/catalog.json`; panel's STATE_DIR, TG_IDENTITY and TG_STATUS are derived
from configuration. Personal top-level paths are inventoried without following
links. Writable paths outside the root or beneath reserved updater/release/resource
entries are INCOMPATIBLE before stop; external read-only system CA remains allowed.
A shared-secret TG installation does not require an enrollment identity file;
its actual status file is still checked. Secrets are never printed or journaled.

Health-rules checks exact own datapath mangle/NFQUEUE/bypass/MASQUERADE contracts,
configured PPE rules, every TG IPv4/IPv6 prefix and both NAT/filter hooks using
read-only queries. Missing expectation fails rather than repairing during health.
A managed stop confirms all owned interception rules are gone and waits for every
recorded state writer to terminate; a failed query/removal is not successful stop.
Legacy IPv4-only mangle handling is retained. Runtime binaries/assets/voice blobs/
TG default CA and helper binaries are pinned to one resolved release root.

Managed uninstall runs stop and DNS removal inside the same lock and preserves
live personal state with D2K_KEEP_STATE=1. Full removal retains update-state's
maintenance inode so concurrent waiters cannot lock a replacement inode. Code,
owned hooks and heartbeats are removed; the retained coordination directory is
an explicit reinstall/recovery prerequisite, not an ordinary flat installation.
The lifecycle handshake below quiesces the real daemon and supervisor before
removing managed code; its isolated Linux fixture executes that path.

Both stable boot and external lifecycle/NDM recovery initialize their production
monotonic clock, boot identity reader and checked private runtime directory via
`d2ku_service_recovery_context`. The returned directory FD is CLOEXEC and must be
closed by its caller. Configuration alone does not initialize these resources.
Explicit `engine-restart` persists the enabled core/datapath bits before starting,
so later capture and boot-start retain the administrator's intent.

Historical wire12 uses profile `flat-wire12-2026-10-04`, authenticated locally
by the owner's existing code, not by an invented historical publisher manifest.
The supported roles are static executable ELF of one supported ABI, bounded
`d2kd --help`, `d2kc` missing-required-argument usage/exit2, panel `--version`
with telegram-control and TG `--version` with per-install-enrollment. Probes
have fixed argv, 5-second/16-KiB bounds and transient group ownership. An
additional event-free private AF_UNIX controller probe must reject wire13 and
accept wire12. Its catalog/live/cache/log paths live in a fresh mode0700 scratch
directory, never live state; no target/event is supplied. Each greeting is
bounded to4 seconds plus1 second TERM grace, then group kill/reap; the log cap
is16KiB. Registration on FD5 precedes child execution. Live
pidfiles bind actual `/proc/PID/exe` to the still-current flat inode and copied
bytes even when enabled intent exists. Core control/catalog/live and runtime
log/resource options must match the supported paths. External writable personal
paths and dynamically loaded old dependencies are unsupported before stop.
Root authorization does not prove original publisher provenance; a malicious
root/bootstrap is outside this integrity model.

The dedicated private receipt is exactly:
`D2KV1 flat-wire12-2026-10-04 ID ABI OLD_HASH RELEASE_HASH RESOURCES_HASH CHECKSUM\n`.
All hashes are lowercase SHA256 hex. Checksum covers preceding bytes excluding
its separator. Canonical bounds and ABI are validated. Release `.d2ku-legacy`
must equal `update-state/legacy-source` byte-for-byte; a simultaneous D2KR1 is
invalid. Before old code executes, the adapter rehashes all saved code, resolved
release code and original root `files/` resources. The tree digest sorts names,
binds each NUL-terminated name, directory mode/type, regular mode/size/content
and directory end markers, refuses links/special files/unsafe owners, and
checks held-file identity and timestamps. Source resources using the reserved
`.bootstrap-`, `.legacy-` prefixes or `.d2ku-legacy` name are refused before copy.
On resume, only regular, single-link, owner-safe temporaries matching exact
`.bootstrap-PID-COUNTER` or `.legacy-PID` decimal grammar are removed from
bootstrap-private construction trees before sealing; all final resources remain
in the complete seal. Bounds: depth12, 4096 entries,
1024 entries per directory, 128MiB per file. Only root `.d2ku-legacy` is excluded.
Legacy ID is `legacy-local-` plus first32 hex digits of full old inventory hash;
full hash, not shortened name, is journal/receipt authority. D2KL1 remains the
independent lifecycle intent format.

Wire12 bootstrap performs **safe preparation only**: seals source and trusted
stable inputs, installs guards/current aliases and persists disabled mask, but
does not stop old runtimes, snapshot live personal data or install a new runtime.
CLI explicitly reports preparation only. Task9's sealed first-worker pair uses
this same exact old receipt identity; no extra Task8 bootstrap entry is needed.
The first new candidate must pass ordinary signed index/manifest/package,
wire13/offline checks before STOPPING. New health never falls back to legacy.

Before coherent snapshot, the adapter enumerates historical runtimes, old
helper PID files, known NDM/init/helper invocations and descendants. Runtime
executables bind the saved release or exact original bytes. Helpers are stopped
before platform stop, rechecked afterwards, and an unknown writer fails closed.
Forced kill, remaining/new writers, unreadable/overflowed stop diagnostics or
controller catalog-save error prevents snapshot-ready/candidate start. Original
root `files/` stays sealed because old voice code has hardcoded resource paths;
new signed code continues to use release-pinned resources.

Immediate recovery selects old health only from validated journal kind1 and
matching old receipt. Datapath greeting is verified wire12 with SO_PEERCRED
before the old core connects, never via a second controller on a live pair.
Bounded startup readiness precedes a real120-second observation: stable proc
inode/start ticks/non-stopped state, owning NFQUEUE socket, progressing datapath
main-loop stats and controller live publication, required state, panel HTTP and
own enabled rules. Old TG requires its process-owned listener and known
connecting/connected status; this is **not** a main-loop pulse or relay/application
success. Status exposes `current.provenance=legacy-local-v1`, `legacy_restored`
and that limitation; `installation_healthy` remains false for this weaker proof.
Legacy is never a remote target or late rollback selection. Durable D2KI1 result,
command replay, quarantine reason and startup ownership fences remain unchanged.


## Daemon, feed configuration and asynchronous IPC (Task 9)

The C daemon is `d2k-update serve`. Modules separate platform/configuration,
signed feed/downloads, operation dispatch/scheduling, safe status serialization,
IPC transport, automatic reservation, and lifecycle coordination. Stable boot
continues to link no curl. Production root is `/opt/d2k`; explicit standalone
`--root DIR` / `--fixture-config FILE` are fixture controls, never HTTP fields.
Required production configuration absent/invalid means unavailable and fail-closed.

Task 8 provisions bootstrap-owned `boot/update.conf`, a regular single-link file
owned by the updater UID (root in production), not writable by group/other, at
most 16 KiB. This is strict data, never shell-sourced:

```
D2KU-CONFIG-1
feed=https://<allowed-host>/<channel-path>
ca=/absolute/public-ca-bundle
abi=<target-abi>
build=<positive-UTC-build-timestamp>
host=<allowed-host>
key=<64-lowercase-hex-public-key> <not-before-UTC> <not-after-UTC>
```

Feed/CA/ABI/build are unique required keys; host/key may repeat within the public
header bounds. Unknown/duplicate scalar keys, invalid values and non-HTTPS feed
fail. No production key is invented by Task 9. Releases cannot replace this
bootstrap trust input. Accepted publication/time floors and key transitions load
from independent durable state before every verification, and become live only
after persistent store succeeds. `/stable.json[.sig]` and
`/<release-id>/manifest.json[.sig]` are fetched with the existing strict HTTPS
transport; detached signatures are exactly 64 raw bytes. Package artifact paths
come only from the authenticated ABI entry. Rechecking install metadata may
return conflict/expiry/replay requiring a new displayed selection; it never
substitutes a different ID/hash. Current selection occupies one bounded in-memory
manifest/index slot and is pinned while work is in flight. Restart requires a
fresh check to select an install, but never resets independent trust floors.

The one durable `update-state/prepared-package` is a raw archive, not authority.
Every reuse checks regular-file owner/mode/link count, signed exact size and full
SHA-256 from freshly verified metadata. Its bounded `.new` is fsynced before
rename and directory fsync; partial `.new` is never reused. A mismatch is removed
and refetched only as part of an already accepted operation (automatic work must
have a new valid reservation). Worker serialization prevents in-flight eviction.
Metadata uses one fixed temporary, removed after each fetch. Force checks cannot
accumulate history/download files.

Linux trusted synchronization uses `adjtimex`, real monotonic clock and boot ID.
Without an initially supplied TZ, the bounded POSIX string in `/etc/TZ` is loaded
and refreshed for every calendar snapshot; initial explicit TZ remains
controlling. Validation/setenv/tzset/localtime share one process mutex, including
all scheduler/feed/transaction clock snapshots. Configured service runtime and
health dirfd refresh per operation under maintenance and again before transaction
stop. Configuration storage belongs to the long-lived daemon, never a returned
stack address. Unsynchronized time blocks manual and automatic installation with
safe `last_error`; metadata status reads never trigger work.

Unix socket: `update-state/updater.sock`, mode 0600, owner/peer UID validated
on both ends (root in production). Frame header is ASCII `D2UI`, u32 big-endian
version 1, u32 big-endian payload length. Request is exactly 166 bytes:
command/force/enabled/reserved u8; release ID in 65 NUL-padded bytes; raw manifest
hash 32 bytes; optional operation ID in 65 NUL-padded bytes. Commands 1..6 are
status/check/install/rollback/settings/quiesce. Reply payload starts with u32
big-endian status code then safe UTF-8 JSON, at most 131072 total bytes. Reads,
writes and frame sizes are bounded. HTTP JSON body is at most 16384 bytes,
strict scalar object with duplicate/unknown/nested fields rejected.

- `GET /api/update`: passive safe state only.
- `POST /api/update/check`: `{"force":false}` (default false).
- `POST /api/update/install` and `/rollback`: required `release_id` and
  64-lowercase-hex `manifest_sha256`.
- `POST /api/update/settings`: required Boolean `enabled`.
- Mutating JSON may additionally contain bounded ASCII `operation_id`.

Existing panel control/same-origin policy applies: missing/bad Origin or disabled
control 403, wrong method 405, oversized body 413, invalid command 400, accepted
work 202, conflicting selection/operation 409. Unavailable updater is a separate
503 state. Multiple clients join one in-flight compatible operation. A supplied
operation ID is preserved; different payload under the same retained ID conflicts.
Without one, the daemon generates a random 128-bit ID. `daemon-result` (D2KD2,
canonical bounded mode0600 atomic/fsynced text) retains the last accepted command
and result across restart. The journal itself retains the canonical transaction
command and release/hash binding across later checks. Every mutating command
checks a matching retained journal operation ID before routing: different command
or payload conflicts, including check/settings reusing an install ID. Acceptance
or pretransaction failure of another request never replaces the old journal
binding. The first durable journal of the new transaction replaces it.
`daemon-transaction` is no longer written or used as replay authority. Matching
retained terminal journal replay returns the existing operation, never repeats install. The bounded
retention contract covers the last operation and current journal generation;
clients must poll status after reconnect rather than retry installation.

Status supplies operation ID/busy, numeric journal phase, actual download bytes,
current/previous release IDs (previous includes rollback hash), available signed
version/notes/hash/compatibility, cache `cached`/`fresh`/result/last-success UTC,
last result and safe error text, enabled/window/selected date/minute/timezone.
Current/previous release IDs are authoritative installed generation identifiers;
bootstrap inventories need not have a friendly signed version label. Notes are
JSON-escaped. A successful settings action cannot erase a retained failed check:
state/error still reflect the check failure, and "current" requires a fresh
successful check matching the current release. Secrets, URLs and configuration
contents are not exposed.

Additional status fields:

- `quarantine`: `{active, applies_to_available, manifest_sha256, reason}`. Inactive
  hash/reason are empty strings. `applies_to_available` requires an authenticated
  available candidate with exactly the durable quarantined manifest hash. Reason
  is safe text mapped from the durable cause enum, never a previous unrelated
  journal or raw log.
- `last_installation`: null or `{operation_id, release_id, result, phase,
  completed_utc, reason}` for the last completed install/rollback **request**,
  including metadata/download failures. Result is d2ku_rc, phase is the matching
  journal phase or 0 before a transaction. Check/settings never replace it.
- `completed_utc`: identical alias of last_installation.completed_utc, or null
  with no known outcome. It is an integer UTC timestamp only when the completion
  clock was trusted; otherwise null. Check-success time, transaction start time,
  and restart time are never substituted.

One independent `update-state/installation-result` stores the outcome in bounded
canonical D2KI1 text (at most 511 bytes, regular/single-link/owner mode0600):
`D2KI1 COMMAND OPERATION RELEASE HASH RESULT PHASE UTC CHECKSUM\n`.
HASH is 64 lowercase hex manifest bytes, COMMAND=3|4, RESULT=0..12, PHASE=0..13,
UTC=0..INT64_MAX (0 means unknown), and CHECKSUM is SHA-256 of all bytes before
its separating space. The atomic private `.new` is fully written and fsynced,
renamed, then the parent directory fsynced before completion is exposed. Format,
ranges, checksum and canonical encoding are validated on load; corrupt outcome
fails closed. The record is bounded independently of metadata/release history.

The daemon writes this outcome before its generic completion record or any new
mutation. Outcome/storage failure blocks subsequent mutating requests so the
unresolved installation cannot be overwritten by check/settings. Restart
reconciles the retained request with a matching journal; an interrupted request
with no durable completion timestamp gets null, even if COMMITTED/ROLLED_BACK
establishes its terminal result. A successfully persisted matching outcome keeps
its real timestamp if the crash occurred before the generic completion write.
Readonly candidate probes reconcile only in memory and never write these files.

CLI fixed forms: `status`, `check [--force]`, `install ID HASH`, `rollback ID HASH`,
`settings on|off`; mutating commands accept trailing `--operation-id ID`.
`service ACTION` forwards fixed validated argv to the stable adapter, and
`service install ID HASH` requires explicit selection. The old managed installer
therefore cannot claim installation success without a selected ID/hash. Task 12
should document the structured CLI; Task 10 supplies the panel controls and stores
one operation ID per user action, reconnecting by status rather than retryinstall.

## First worker, postcommit handoff and uninstall ownership

Authenticated bootstrap bundles may contain the pair `d2k-update-first` and
`update.conf`. Both are sealed in bootstrap input and installed into immutable
`boot/`; Task 8 supplies the real first daemon and production config. First-worker
execution requires exact bootstrap.done inventory/current receipt identity,
matching sealed first/config bytes, no signed committed generation, and no
`first-retired` marker. A missing daemon in signed current never re-enables
fallback, even if journal generations rotate. The first signed commit durably
retires fallback. Both ordinary wire13 and typed historical wire12 local
inventories can anchor the first worker; neither becomes publisher-signed.

Old worker owns the transaction through commit and candidate probe. Exit75 is a
handoff request only: supervisor must verify newer durable COMMITTED journal,
old generation equals the worker's initial current, new generation differs, and
current receipt matches journal ID/hash. It kills/reaps owned/registered groups
before handing off. Stable boot retains `supervisor.lock` across worker changes,
refreshes config/runtime and launches new current with independent heartbeat.
No same-generation exit75 restart loop is accepted. Postcommit startup failure
leaves an explicit stopped/unavailable state; it never late-restores old state.

Managed uninstall holds maintenance and sends internal QUIESCE with exactly one
SCM_RIGHTS descriptor for that same held lock description. Receiver rejects extra
or stray descriptors, validates maintenance inode/description and closes all
received descriptors on reject. Under dispatch mutex it refuses pending work,
sets quiescing, and fsyncs D2KL1 intent bound to operation ID, worker PID and boot
ID after confirming terminal/no transaction. Other lifecycle entrypoints refuse
mutations while the marker exists. A worker's arbitrary exit76 cannot bypass
normal recovery: stable supervisor authenticates intent/PID/boot and terminal
journal, reaps groups, then fsyncs stopped ACK **without reacquiring maintenance**.
The remover waits for stopped ACK and both daemon/supervisor lock release before
removing code. Normal service stop preserves updater supervision.

D2KL1 contains stopped bit, worker PID, boot ID, operation ID and SHA-256 checksum,
strict bounded canonical text, fsynced atomic file. An interrupted remover leaves
an explicit lifecycle marker: ordinary bootstrap/service startup fails closed.
Explicit uninstall may resume under maintenance only after both ownership locks
are idle, retaining the original intent binding after confirming exclusive idle ownership;
this also handles remover
loss after intent/worker exit. Removal preserves the independent coordination
state and never silently restarts a quiesced installation.


Startup ownership is fenced against removal by shared maintenance. Both daemon
and supervisor acquire maintenance, reject any lifecycle marker (including an
invalid one), then claim their validated lifetime ownership lock before releasing
maintenance. Daemon retains maintenance through persistent initialization,
runtime refresh and socket publication; lifetime daemon.lock remains held until
worker/socket cleanup. Stable --daemon and --supervise retain supervisor.lock
before configuration/runtime mutation or recovery/worker fork and across handoffs;
they release startup maintenance before calling recovery, which takes its own
maintenance lock. Candidate --boot-probe stays readonly and claims neither public
ownership nor transaction maintenance.

Thus a no-worker remover can inspect idle locks and fsync intent/stopped ACK while
holding maintenance without a delayed startup entering between those steps. A
starter paused before ownership sees the marker after resuming and cannot create
its lock/socket or run a worker after code removal. If startup claimed first,
remover refuses or follows authenticated quiescence of that owned process.
`check-startup-fence` exercises all three actual CLI paths with private pipe
barriers in `D2KU_TEST_STARTUP` builds; those hooks are absent from ordinary builds.
