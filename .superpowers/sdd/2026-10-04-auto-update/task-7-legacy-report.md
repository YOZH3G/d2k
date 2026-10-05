# Task7 historical wire12 extension — implementation report

2026-10-05. Base `71bd2268fd8ab4f0bdb819557e9b6037713fe166`, branch
`feat/telegram-tunnel`. This implements the accepted legacy brief/design without
reopening approved wire13/fix1, Task9 or Task10 scope. Final owned commit is
reported by the handoff message (this report is part of that commit).

Foreign dirty preserved and excluded: `.impeccable/config.json`, its untracked
hook/mocks/review files, `panel/test_router_view.cjs`, and
`docs/field/2026-10-02-vedomost-demo.md`. No subagents, router access, production
keys, downloads, publishing, host rules or unrelated core/detect/datapath suites.
Task8's separate worktree/build outputs were not changed.

## Implemented contracts

- `D2KV1 flat-wire12-2026-10-04` receipt is a distinct owner-authorized local
  source. Full original inventory hash, complete resolved release hash, retained
  original resource hash, ABI and exact private root anchor are checked before
  executing old code. No invented published old manifest/hash whitelist. Static
  ELF, one ABI, known CLI, held-file copy stability and actual live flat inode /
  saved-byte binding are required. Unsafe links/ownership, unknown writable
  paths, mixed copied/running identity or unsupported profile refuse before stop.
- Known controller protocol is proved by a private event-free AF_UNIX fixture:
  reject13, accept12. Scratch catalog/live/cache/log are explicit fresh private
  paths; no live pair connection, target, queue or network probe. Each greeting
  has4-second deadline plus1-second TERM grace, then group kill/reap; output
  log capped16KiB. CLI probes are5-second/16KiB fixed argv. FD5 registration
  precedes execution, and child FDs3/4/5 are closed. Actual recovery independently
  validates datapath wire12 greeting and SO_PEERCRED before starting old core.
- `D2KB2` adds explicit sourcekind. Journal appends `old_kind u8` after existing
  command u8; unknown/missing kinds fail closed, legacy is install-only and only
  old source. Persistent quarantine reason u32, D2KI1 outcome, D2KL1 lifecycle,
  operation replay and startup/lifetime fences remain intact.
- Historical bootstrap is preparation only: seals old code, trusted boot input,
  guards/current aliases and service mask, without stop, live personal snapshot
  or unsigned runtime replacement. Diagnostic says so. Task9 first worker still
  requires the sealed first/config pair and pinned old receipt; signed new
  index/manifest/package and ordinary wire13 offline/health checks precede stop.
  A new target can never request or fall back to legacy health; legacy is not
  offered for late rollback.
- Before snapshot, C finds old runtime/helper PID files, known old NDM/init/helper
  invocations and descendants, terminates helpers before platform stop, and
  checks all recorded writers again afterwards. Unknown/new/live writers,
  forced stop, unreadable/overflowed diagnostics or catalog-save errors prevent
  snapshot readiness. Fixed validated platform commands remain shell adapters;
  all new orchestration is C. Personal config/catalog/identity/status paths and
  disabled mask are preserved. Original `files/` stays sealed for old hardcoded
  voice paths; new resources remain pinned to the signed release.
- Real120-second old recovery checks stable process executable/start ticks,
  non-stopped state, owning NFQUEUE socket, advancing datapath main-loop stats
  and controller live publication, local panel HTTP, required state and all
  enabled own rules. A separate bounded startup interval handles PID-before-exec.
  Old TG evidence is explicitly only process-owned listener + known status;
  it is not a main-loop heartbeat or application/relay success. Status exposes
  `legacy-local-v1` / `legacy_restored` and the weaker evidence; it does not set
  signed `installation_healthy`.
- Crash recovery removes only verified updater temporary names from private
  construction trees. Source resources with reserved names are refused before
  copy, so legitimate source data is never silently omitted/deleted. All normal
  source and release files remain covered by the seal.

Canonical encodings, ownership, path, health and packaging details are in
`update/FORMAT.md`. Focused new C modules are legacy_inventory/probe/protocol/
quiesce/health; no new runtime executable or external shell payload API.

## RED → GREEN evidence

1. `task7-legacy-red.log`: first typed inventory test did not compile before
   legacy API existed. `task7-legacy-abi-red.log`: mismatched context ABI was
   initially accepted; the assertion failed. Typed receipt tests now cover ABI,
   complete saved/release/original resources, added files, modes, symlinks,
   hardlinks, conflicting ordinary receipt, anchor corruption and4 receipt
   durability cuts, plus journal kind/command round trip and unknown-kind refusal.
2. `task7-legacy-historical-red.log`: actual new historical CLI fixture against
   immutable base71bd226 boot/adapter exits1: baseline explicitly rejects wire12
   before stop. This used `git archive 71bd226... update runtime` into private
   `/baseline`, independently compiled there; no product revert.
3. Actual first-transition fixture initially reached recovery with PID published
   before controller exec/live state, then RECOVERY_FAILED. Bounded startup
   readiness fixed that race; full real120s recovery subsequently passed. The
   early failed output was observed in exec session96626; it was not archived
   separately. Do not equate it with the retained complete GREEN raw log.
4. `task7-legacy-crash-red.log`: SIGKILL cut103 of141 leaves a private copy temp
   under release/files; final source validation returned RECOVERY (the final
   successful bootstrap count was141). Fix cleans exact owned temporary names
   before sealing, refuses reserved source names and revalidates anchored source
   before publishing. `task7-legacy-crash-green.log` records all141 cuts passing;
   the final Linux log repeats them with the later protocol admission guard.
5. `task7-legacy-mixed-wire-red.log`: pre-protocol-guard boot admitted old DP plus
   prepared wire13 controller because CLI shape matched. The final guard rejects
   that combination before pending/current/stop; actual historical controller
   accepts12/rejects13 in private scratch. `task7-legacy-protocol-green.log` is
   the first real historical GREEN after adding that guard.
6. `task7-legacy-check.log` is an earlier non-final full run interrupted by a
   compile error while a field-name edit was in progress (`s->queue` corrected
   to `s->ctx->health_queue`). Kept unchanged as evidence, not a passing run.

## Commands and results

All scenario headers/arguments were read. Linux image is
`d2k-update-lab:bookworm`; container `d2ku-legacy-work` was created with:

```
docker run -d --init --name d2ku-legacy-work --network none \
  --cap-add NET_ADMIN -e D2KU_LEGACY_LAB=1 d2k-update-lab:bookworm sleep infinity
COPYFILE_DISABLE=1 tar -cf /tmp/d2ku-legacy-work.tar \
  update runtime files scripts/uninstall.sh build/task7-legacy/builds
docker cp /tmp/d2ku-legacy-work.tar d2ku-legacy-work:/tmp/source.tar
```

Extracted into private `/work`. Subsequent source changes were transferred by
`tar`/`docker cp`, never a `/Library` or host `/opt` mount. Private `/opt/d2k`,
NFQUEUE30000, own iptables chains, AF_UNIX sockets and loopback are container-only.
No external targets or packets were supplied. Container `--init` reaps service
children. Final commands inside `/work`:

```
make -C update CFLAGS='-O2 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -Wno-misleading-indentation -Wno-format-truncation' \
  boot service-adapter ../build/update/test_legacy_crash \
  ../build/update/test_legacy_transition ../build/update/legacy_candidate
python3 update/tests/test_legacy_linux.py build/update/d2k-update-boot \
  build/update/d2k-service-adapter build/task7-legacy/builds \
  build/update/test_legacy_crash
# Remove only prior stopped private container fixture, then:
python3 update/tests/test_legacy_transition_linux.py build/update/d2k-update-boot \
  build/update/d2k-service-adapter build/task7-legacy/builds \
  build/update/test_legacy_transition build/update/legacy_candidate
```

Two warning suppressions are the established GCC fixture flags, not source
changes. `task7-legacy-final-linux.log` exits1: all141 preparation cuts and the real120s
transition/negative health checks passed, but its trailing external service stop
failed. That log is preserved as a nonzero run, not relabeled GREEN. The scoped
follow-up and final covering transition are described below.
Earlier full Linux GREEN is `task7-legacy-linux-green.log`, exit0, before the
last protocol-admission guard. It includes141 crash cuts, real signed Ed25519
index/manifest/tar, actual old runtime, production transaction/adapter, failed
candidate start after coherent snapshot/current switch, restored old runtime
for120s, retained HEALTH quarantine, disabled panel/TG and personal identity,
pre-guard helper termination, and negative frozen-DP/controller/missing-own-rule/
wrong-target/strict-wire13-health tests. No mock health, clock, offline or service
callbacks are used in that transition. Only the test clock's synchronized UTC
sample is explicit; monotonic time and boot identity are production reads.
The signed test candidate is deliberately a small offline-compatible ELF whose
signed platform start fails; it is not represented as a successful new runtime.

Host checks:

```
make -C update check
make -C update BUILD=../build/update-task7-legacy-san \
  CFLAGS='-O1 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined' check-legacy check-journal check-bootstrap
git diff --check
```

`task7-legacy-check-green.log` and `task7-legacy-san-green.log` both exit0 before
last protocol guard. Final covering reruns after that guard are
`task7-legacy-final-check.log` and `task7-legacy-final-san.log`, both exit0. Full updater includes Task9 replay/outcome/lifecycle/auto/platform/feed
checks; sanitizer scope includes new inventory, journal and bootstrap/managed
CLI paths, not unrelated whole-project sanitizer suites. `git diff --check`
passed before final report. Earlier historical fixture/protocol logs are distinct
from final runs, and all RED originals are retained.

## Historical fixture provenance

Actual historical ARM64 ELF, no synthetic legacy heartbeat/identity wrapper:

| Role | Local provenance | SHA256 |
|---|---|---|
| d2kc | `/tmp/d2k-voice-release/d2kc-linux-arm64`, matches Oct04 field report | `deb6ed43d9ea1f9dc40b0abde2fc2fd2751344e5d6f7347dca9f14e9fd186a7a` |
| d2kd | `e10a017:builds/d2kd-linux-arm64` | `02da8d36db4e3b80be12a943766b8a35a565bf048dc65230e59a5aca6d7ead24` |
| d2kpanel | `e10a017:builds/d2kpanel-linux-arm64` | `d0e7fc87294009f828483c489ab3a7544bb4dc94ca0788dfcce7d88c42df3425` |
| d2ktg | `e10a017:builds/d2ktg-linux-arm64` | `bf0d424b157c8da1c8bd4465c0569d86628deff0d04ed7379b451144ee7dbfb2` |
| mixed-wire negative d2kc | `71bd226:builds/d2kc-linux-arm64` (prepared wire13) | `dfa5fe3ec4769e9d0326bd860381ddf4bcc980e425a3e25a7b2637bfb6cb4718` |

The DP is **not** the exact field-reported DP hash `1c819496...`; it exercises the
historical wire12 capability, not a claim that the full field installation was
reproduced. Local admission intentionally accepts a safe owner-authorized
inventory rather than requiring a retroactively published whitelist. Fixtures
use current fixed platform adapters and private resources, not a historical
publisher-signed complete old package.

## Integration prerequisites and limits

Task8 needs **no extra bundle entry or configuration key**: keep15 bootstrap
files/ABI (including paired first worker/config) and26 ordinary signed runtime
files/ABI. Rebuild boot, adapter and first/update worker together from this
schema revision: D2KB2, D2KV1 and appended journal kind are coordinated pre-release
contracts, not backward guesses at missing tails. The new C sources are linked
by TRANSACTION_SRC; OpenSSL/curl dependency/ABI contract is unchanged. First
worker still needs real authenticated distribution config/trust. No production
feed/key/distribution is created here; bootstrap input is explicitly verified
local installer input, never an HTTP-supplied unsigned bundle.

Wire12 support is for the named static CLI/resource profile, not arbitrary old
versions, dynamic library layouts, external writable personal paths or divergent
live argv. External read-only system CA is allowed. Active adversarial root is
outside the local integrity model. Full hashes before legacy script execution
add I/O cost; router performance is unmeasured.

Laboratory proof is not field acceptance. The real120s enabled-engine fixture
keeps panel/TG disabled; their historical offline CLI is real, while active
legacy panel/TG120s and relay/application success are not claimed. Old TG's
missing heartbeat cannot be manufactured. Existing ordinary adapter tests cover
all67 missing-rule cases, including TG interception; they are not a live old TG
field test. Historical first transition after failed start and every bootstrap
barrier are exercised; every transaction failure phase with real old runtimes,
old NDM scheduling races and forced-kill/save-error injection are not claimed as
separate full120s tests. Common transaction crash/rollback tests remain in the
full updater suite. No MVP/field checklist item is closed here. Independent
review remains the next gate before Task8 packaging.


## Final lifecycle-stop regression and minimal fix

The nonzero trailing stop was reproduced independently with actual
`boot-start -> stop`: `task7-legacy-stop-reproduce.log`, exit1. Private container
instrumentation added `/bin/sh -x` only to a temporary copy of service_adapter.c
and rebuilt the container adapter; `task7-legacy-stop-trace.log` shows
`stop_pidfile(d2k-log-maintenance.pid)` waiting30*0.1s then setting forced=1 and
returning failure after KILL. No trace instrumentation entered product files or
final binaries; the original adapter source was copied back and rebuilt.

Cause: legacy collect skipped *all* adapter waiters before classifying captured
helper descendants. A log helper shell deferred TERM while waiting on its own
adapter child, which was blocked by this stop's maintenance lock. The minimal
change classifies ancestry first: adapter waiters that descend from captured
old helpers are quiesced with that tree; independent external waiters remain
excluded/alive. Forced-kill and save-error refusal is unchanged.

The exact `boot-start -> stop` repeat with production adapter passed exit0 in
`task7-legacy-stop-green.log`. The transition fixture now sets LOG_EVERY=1 and
also holds the real maintenance FD4 while launching an unrelated external
status waiter. Internal stop must quiesce helper adapter descendants while that
independent waiter stays blocked/alive; only releasing the lock lets it finish.
It then checks external stop too. Its raw covering rerun is
`task7-legacy-stop-transition-green.log`. Despite its filename this harness exits1:
the production C transaction and negative health checks pass after real120s,
then the newly added independent-waiter fixture returned BUSY. It launched the
unrelated waiter from `/work/build/update/d2k-service-adapter`, whereas real
init/NDM/helper entry points use the installed `root/boot/d2k-service-adapter`
inode. The production allowlist correctly refused the unrecognized executable.
FD4 ownership was valid. This second nonzero log is retained unchanged.
Post-fix ASan/UBSan `check-legacy check-bootstrap` uses the same sanitizer flags
above, raw `task7-legacy-stop-san.log`, exit0.
The last full updater/journal sanitizer runs were before this narrow
quiesce-descendant change, and are distinguished from these covering repeats.


Corrected only the fixture's waiter executable, factored into
`update/tests/test_legacy_waiter_linux.py` and called by the full transition
harness. No product change followed the descendant-waiter fix. Exact isolated
covering command, against the same prepared/running real legacy fixture:

```
docker exec d2ku-legacy-work sh -c 'cd /work; python3 update/tests/test_legacy_waiter_linux.py build/update/d2k-service-adapter /opt/d2k'
```

`task7-legacy-waiter-green.log`: exit0; both internal stop and subsequent external
stop succeed; the installed independent waiter remains alive until lock release.
The complete surrounding120s Python harness was not repeated after this
fixture-only inode correction: its post-product-fix C120s transaction result and
negative health were already PASS, and its corrected cleanup component now has
its own observed exit0. Root/controller accepted these covering checks as
sufficient before commit. No log's filename overrides its actual exit status.

Final evidence summary:
- Full updater after protocol admission: `task7-legacy-final-check.log`, exit0.
- ASan/UBSan legacy/journal/bootstrap after protocol admission:
  `task7-legacy-final-san.log`, exit0.
- New typed bootstrap SIGKILL: all141 cuts PASS in final-linux before its
  separately identified later stop failure.
- After final product fix: actual signed transition→old wire12 real120s recovery
  and negative health PASS in stop-transition log; exact lifecycle repeat exit0;
  ASan/UBSan legacy/bootstrap repeat exit0; corrected independent-waiter test exit0.
- `sh -n files/S99d2k`, Python AST parsing, and `git diff --check`: exit0.
- Container image ID:
  `sha256:8b8a35e2b51eedfada013b86ea6e20d9dd8fe147e0c8c614efe10b4c9f62a20c`.

Raw logs stay in the ignored local `.superpowers/sdd/2026-10-04-auto-update/`
workspace evidence directory. The owned report is committed explicitly; logs,
fixture binaries, container/debug artifacts and all foreign dirt are excluded.

## Independent legacy review fix round 1 — 2026-10-05

Base `87c742e823fb7cf272cce482c7217d7ebf457a1e`, same branch and foreign
working-tree dirt listed above. All three Important findings in
`task-7-legacy-review.md` were reproduced and fixed. No router/host-rule/service
changes, subagents, package additions, keys or external publication. Task8's
15/26 file inventories, receipts/journal schemas and ABI dependencies are unchanged.

### Changes and actual historical defaults

1. Active panel/TG admission now uses actual historical S99 log names
   `panel.log` and `telegram.log`. The Linux bootstrap fixture starts both real
   historical ARM64 binaries, checks they remain alive across preparation, and
   still checks disabled intent/personal files/tamper refusal. The fixture runs
   only with `D2KU_LEGACY_LAB=1` in `--network none`; panel listens on loopback
   127.0.0.1:18090 and receives no HTTP/API requests. TG listens on its historical
   fixed port1443 and tries only closed loopback `wss://127.0.0.1:1/ws`, using
   fixture-only credentials and system CA. There is no external relay/target.
   These are admission checks, not an active TG application/120s proof.
2. Live argv is bounded to8192 bytes/64 arguments and parsed completely by role.
   Unknown/cross-role/duplicate options, missing values, bad numbers and divergent
   effective resources/settings refuse before entry changes. All historical
   panel resource switches are checked, including assets/state/service/pid/status.
   Actual CLI defaults come from e10a017 `panel/main.c`, `core/d2kc.c`, datapath
   and Telegram CLI, compared with current configured S99 profile. DP config
   marks/flows, mode/queue and panel listen/state are retained; explicit default
   DP tuning options are accepted, unsupported nondefault tuning refused.
   `--stats` remains diagnostic-only and becomes1 on recovery as previously.
   The known S99 profile explicitly passes marks/reverse-hook; the transition
   fixture now does the same. The historical cache is `state/https-cache.txt`,
   not the earlier synthetic fixture `.json` path. Controller defaults and
   explicit optional default cache are tested.
   Historical panel does NOT consume config `TG_STATUS`; its default remains
   root/state/telegram.status, while the TG daemon's configured status is still
   snapshotted. Missing panel MODE means observe unless config supplied MODE;
   missing STATE_DIR means /opt/d2k/state unless config supplied STATE_DIR.
   These distinctions have addressed RED→GREEN tests. Config is not rewritten.
3. Before stop, diagnostics bind to actual live controller FD1 AND FD2, retained
   executable/start ticks, and the held owner-safe regular single-link log inode.
   Captured helper descendants must exit (bounded3s, no forced-success path)
   before offset. FD/inode/path are rechecked after their exit, including a helper
   that replaces the pathname during TERM. The pinned prefix is SHA256 streamed
   in16KiB chunks, capped at the existing inventory128MiB/file limit. After stop,
   missing/replaced/truncated/rewritten prior bytes, NUL/overflow/unreadable new
   diagnostics or actual catalog/HTTPS-cache/HTTP-plan save-failure text fail
   closed. Already absent core has no pending writer/flush to prove. Independent
   external installed-adapter waiters remain excluded; captured descendants are
   still stopped. The signed target and typed legacy120s health paths are unchanged.

### RED evidence, retained unchanged

All logs below are beside this report with prefix `task7-legacy-fix1-`.
The real historical fixture command is:

```
python3 update/tests/test_legacy_linux.py build/update/d2k-update-boot \
  build/update/d2k-service-adapter build/task7-legacy/builds
```

- `active-red3.log`, exit1: healthy active panel/TG bootstrap returned HEALTH10,
  no current alias. After two log-name corrections `active-green.log`, exit0.
  Earlier `active-red.log`/`active-red2.log` are fixture setup errors (duplicate
  TG_ENABLED, then unsupported TG_PORT15443), not product evidence; retained.
- With log fix, `paths-red.log`, exit1: real historical panel redirected
  --state-dir to a private external directory, yet bootstrap succeeded. Final
  fixture checks four live divergences (state-dir/assets/service/telegram-status)
  rejected before current, without stopping that process. `paths-green2.log`
  exit0. The misleadingly named `paths-green.log` is a compile failure from a
  missing test-only fcntl include; `diagnostic-red.log` consequently has127
  (test not built). Neither is claimed GREEN.
- `diagnostic-red2.log`: production before/after with real held writer FDs and
  inode: replaced-before, truncated, rewritten, replaced-after and helper each
  abort134. Normal and exit-zero save-error pass. The C fixture uses an isolated
  writer executable implementing the old exit-zero diagnostic behavior, not a
  mock of quiesce; full real historical core stop is separately covered below.
  `diagnostic-green.log` then passes7 cases; final nine-case
  `diagnostic-final.log` exit0 adds helper replacement and oversized log.
- `panel-default-red.log`, exit134, finds config TG_STATUS wrongly changing
  panel default; addressed in `panel-default-green.log`, exit0.
  `omitted-default-red.log`, exit134, then finds absent MODE wrongly inheriting
  S99's apply default. The final per-role test covers both with real configured
  presence flags. These are narrow final changes after broad covering below.

### Covering gates and exact chronology

Before the final panel TG_STATUS/MODE/STATE_DIR default refinement:

```
make -C update check-bootstrap check-transaction check-recovery check-legacy
make -C update BUILD=../build/update-task7-fix1-san \
  CFLAGS='-O1 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined' check-bootstrap check-legacy
```

`covering.log` exit0:155 bootstrap crash barriers,67 missing-rule cases, real
managed CLI, transaction,37 recovery crash/fsync barriers, offline ownership,
legacy inventory. `san.log` HARNESS_EXIT0, ASan/UBSan bootstrap/managed/argv/
inventory. This round did not repeat unrelated full core/detect/datapath suites.

Fresh container `d2ku-legacy-fix1-final`, same previously recorded lab image:

```
docker run -d --init --name d2ku-legacy-fix1-final --network none \
  --cap-add NET_ADMIN -e D2KU_LEGACY_LAB=1 d2k-update-lab:bookworm sleep infinity
COPYFILE_DISABLE=1 tar -cf /tmp/d2ku-legacy-fix1-final.tar \
  update runtime files scripts build/task7-legacy/builds
docker cp /tmp/d2ku-legacy-fix1-final.tar d2ku-legacy-fix1-final:/tmp/source.tar
```

Inside that private container (no host mounts):

```
mkdir -p /work
cd /work
tar -xf /tmp/source.tar
make -C update CFLAGS='-O2 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -Wno-misleading-indentation -Wno-format-truncation' \
  boot service-adapter ../build/update/test_legacy_transition \
  ../build/update/legacy_candidate ../build/update/test_legacy_quiesce
for scenario in replaced-before truncated rewritten replaced-after helper helper-replace oversized normal save-error; do
  build/update/test_legacy_quiesce "$scenario" || exit
done
python3 update/tests/test_legacy_linux.py build/update/d2k-update-boot \
  build/update/d2k-service-adapter build/task7-legacy/builds
python3 update/tests/test_legacy_transition_linux.py build/update/d2k-update-boot \
  build/update/d2k-service-adapter build/task7-legacy/builds \
  build/update/test_legacy_transition build/update/legacy_candidate
```

`final-linux2.log` HARNESS_EXIT0: all9 diagnostics, actual active panel/TG
admission, actual signed failed target→wire12 rollback with **full120s**,
negative frozen DP/core/rules/wrong-target/new-health checks, helper-descendant
stop preserving independent waiter, trailing external stop. `final-linux.log`
HARNESS_EXIT1 contains only initial `mkdir /work: File exists` setup mistake,
fixed to mkdir -p; retained, not product failure. Historical artifact provenance
and field limitations are exactly those already recorded above.

After the LAST product change (only panel effective-default refinement):

```
make -C update BUILD=../build/update-task7-fix1-san \
  CFLAGS='-O1 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer' \
  LDFLAGS='-fsanitize=address,undefined' ../build/update-task7-fix1-san/test_service_adapter
build/update-task7-fix1-san/test_service_adapter
```

`final-argv-san.log` HARNESS_EXIT0. Updated sources copied by tar/cp into the
same now-stopped private Linux container, then:

```
make -C update CFLAGS='-O2 -g -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic -Wno-misleading-indentation -Wno-format-truncation' \
  boot service-adapter ../build/update/test_service_adapter
build/update/test_service_adapter
python3 update/tests/test_legacy_linux.py build/update/d2k-update-boot \
  build/update/d2k-service-adapter build/task7-legacy/builds
```

`final-active.log` HARNESS_EXIT0: final strict role/default parser and actual
historical active panel/TG plus all four divergent live paths. The earlier full
120s run is explicitly prior to this final parser-only refinement; it is not
mislabelled a post-refinement rerun. Final `git diff --check` passes. No further
runtime changes follow these tests. The next gate is the same independent
reviewer's scoped re-review, then Task8 distribution; no MVP/field acceptance
or new-runtime health fallback is claimed.
