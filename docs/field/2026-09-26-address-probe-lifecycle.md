# Address QUIC trial lifecycle — implementation handoff

Status: implemented and all local repository gates passed. This document
describes code and local evidence, not field acceptance.

## Invariants

- Persistent `SET_ADDR` is confirmed catalog knowledge. A candidate must never
  use it before verification because it would affect unrelated clients sharing
  the destination IP.
- Temporary address probes live in a separate datapath table and match the
  complete UDP flow tuple (source/destination IPv4 and ports, protocol).
- Every candidate attempt gets a fresh nonzero random 128-bit trial ID. The
  stable Plan ID identifies plan contents and is not a substitute for trial
  generation.
- Probe entries have a bounded lease. `DEL_ADDR_PROBE` requires both exact flow
  and exact trial ID; a stale delete is an idempotent no-op.
- `APPLIED` evidence is accepted only when target flow, Plan ID, and trial ID
  match the active candidate. A generic UDP `EXCHANGE` is observation only.
- Promotion requires QUIC application-level verification plus exact `APPLIED`.
  Then the scheduler writes the literal IPv4 target as `kind=addr`, installs
  persistent `SET_ADDR`, and removes only the successful temporary probe.
- Failure, timeout, retry, and scheduler shutdown clean up only the temporary
  generation. Previously confirmed persistent address entries are preserved.

## Implementation map

- Datapath table/API: `datapath/include/d2k_plans.h`, `datapath/plans.c`.
- Version 3 command and event contract: `datapath/include/d2k_ctl.h`,
  `datapath/ctlsrv.c`, `core/include/d2k_link.h`, `core/link.c`.
- Flow/journal evidence: `datapath/include/d2k_track.h`,
  `datapath/include/d2k_journal.h`, `datapath/session.c`, `datapath/journal.c`.
- Reserved socket, exact evidence matching, promotion and cleanup:
  `core/sched.c`.

`SET_ADDR_PROBE` body is `flow(13) || trial_id(16) || lease_ms(u32 BE) || Plan`.
Flow is source IPv4(4), source port BE(2), destination IPv4(4), destination
port BE(2), UDP protocol(1). `DEL_ADDR_PROBE` carries the first 29 bytes. Version
3 `APPLIED` carries `Plan ID(16) || trial ID(16)` after the flow key;
`REFUSED` carries `reason(1) || Plan ID(16) || trial ID(16)`. Ordinary plans use
a zero trial ID.

## Local evidence in this change

- `datapath/test_plans.c`: exact-flow isolation, generation-safe delete, expiry,
  and persistent address survival.
- `datapath/test_ctl.c`: malformed/invalid address probes, valid SET/DEL,
  stale delete, and APPLIED/REFUSED wire widths.
- `core/test_link.c`: outbound SET_ADDR_PROBE serialization plus event parsing.
- `core/test_sched.c`: address candidate uses SET_ADDR_PROBE, not name or
  persistent install; exact trial/Plan/flow evidence and QUIC application proof
  promote an IPv4 `addr` binding; ordinary UDP observation cannot promote it.
  The lifecycle regressions also exercise two simultaneous address tasks,
  retry after a failed candidate with a fresh trial ID and verifier port, and
  task-timeout cleanup without a persistent `SET_ADDR`.
- `core/test_catalog.c`: `kind=addr`, literal IPv4 target, and transport survive
  catalog round-trip.

Final local gate results after the wire-v3 fixture correction:

```sh
make -C datapath check
make -C core check
make -C detect check
make -C core cross
git diff --check
```

All completed successfully. The first full core run exposed two synthetic test
helpers still emitting the pre-v3 short `APPLIED` frame; after adding the
required zero trial ID for TCP name probes, `test_compose`, `test_d2kask`, and
the full sequential core suite passed.

## Explicitly not proven

No router was changed and no field test was run. macOS socketpair tests do not
prove Linux NFQUEUE/SNAT behavior, raw packet preservation, PMTU, or the provider
path. A scheduler regression now rejects stale APPLIED with the same Plan/flow
but a different trial ID. Restart restoration is covered by the catalog sync
run; the new scheduler lifecycle tests cover simultaneous address tasks, retry
with a new trial ID, and timeout cleanup.
Remaining broader MVP work includes cross-datagram QUIC CRYPTO assembly,
non-AES QUIC input parity, remaining independent donor Run parity, and
protocol-level proof for live voice/STUN UDP. Field/router tests require the
owner's separate approval.
