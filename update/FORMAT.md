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
