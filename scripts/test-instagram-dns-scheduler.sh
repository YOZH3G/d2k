#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SCHEDULER=$ROOT/files/d2k-instagram-dns-scheduler.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

mkdir -p "$TMP/bin" "$TMP/d2k/state" "$TMP/d2k/log"
cat > "$TMP/bin/date" <<'EOF'
#!/bin/sh
case "$1" in
    +%Y-%m-%d) printf '%s\n' "${FAKE_DAY:-2026-09-29}" ;;
    +%H%M) printf '%s\n' "${FAKE_HHMM:-0359}" ;;
    +%s) printf '%s\n' "${FAKE_EPOCH:-1790654340}" ;;
    *) exit 2 ;;
esac
EOF
cat > "$TMP/helper" <<'EOF'
#!/bin/sh
count=$(cat "$HELPER_CALLS" 2>/dev/null || echo 0)
count=$((count + 1))
printf '%s\n' "$count" > "$HELPER_CALLS"
[ "$count" -gt 1 ]
EOF
chmod +x "$TMP/bin/date" "$TMP/helper"
run_tick() {
    env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" \
        D2K_INSTAGRAM_HELPER="$TMP/helper" \
        D2K_INSTAGRAM_SCHED_STATE="$TMP/d2k/state/success" \
        D2K_INSTAGRAM_SCHED_ATTEMPT="$TMP/attempt" \
        D2K_INSTAGRAM_SCHED_OFFSET="$TMP/d2k/state/offset" \
        D2K_INSTAGRAM_SCHED_LOG="$TMP/scheduler.log" HELPER_CALLS="$TMP/calls" \
        D2K_SCHEDULER_RETRY_AFTER=1800 sh "$SCHEDULER" tick
}

# A previous day's success: wait for 02:00 router time (offset 0 here).
printf '0\n' > "$TMP/d2k/state/offset"
printf '2026-09-28\n' > "$TMP/d2k/state/success"
FAKE_HHMM=0159 run_tick
[ ! -e "$TMP/calls" ] || { echo 'FAIL: ran before 02:00 local time' >&2; exit 1; }
FAKE_HHMM=0200 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: did not run at 02:00' >&2; exit 1; }
FAKE_HHMM=0210 FAKE_EPOCH=1790654940 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: retried before backoff expired' >&2; exit 1; }
FAKE_HHMM=0231 FAKE_EPOCH=1790656200 run_tick
[ "$(cat "$TMP/calls")" = 2 ] || { echo 'FAIL: did not retry after resolver failure' >&2; exit 1; }
[ "$(cat "$TMP/d2k/state/success")" = 2026-09-29 ] || { echo 'FAIL: successful date not persisted' >&2; exit 1; }
FAKE_HHMM=0500 FAKE_EPOCH=1790657940 run_tick
[ "$(cat "$TMP/calls")" = 2 ] || { echo 'FAIL: refreshed more than once after success' >&2; exit 1; }

# No recorded success (fresh install, or the installer cleared it to pin a new
# host set): refresh in the background right away, whatever the hour.
rm -f "$TMP/d2k/state/success" "$TMP/attempt" "$TMP/calls"
FAKE_DAY=2026-09-30 FAKE_HHMM=0100 FAKE_EPOCH=1790730000 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: first refresh waited for 02:00' >&2; exit 1; }
FAKE_DAY=2026-09-30 FAKE_HHMM=0110 FAKE_EPOCH=1790730600 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: first-refresh retry ignored the backoff' >&2; exit 1; }
FAKE_DAY=2026-09-30 FAKE_HHMM=0131 FAKE_EPOCH=1790731860 run_tick
[ "$(cat "$TMP/calls")" = 2 ] || { echo 'FAIL: failed first refresh was not retried' >&2; exit 1; }
[ "$(cat "$TMP/d2k/state/success")" = 2026-09-30 ] || { echo 'FAIL: first refresh success not persisted' >&2; exit 1; }
# Routers spread over 02:00-02:59 by a stable per-install offset, so the fleet
# does not hit the shared /resolve limit in the same minute.
rm -f "$TMP/calls" "$TMP/attempt"; printf '37\n' > "$TMP/d2k/state/offset"
printf '2026-09-30\n' > "$TMP/d2k/state/success"
FAKE_DAY=2026-10-01 FAKE_HHMM=0236 FAKE_EPOCH=1790820000 run_tick
[ ! -e "$TMP/calls" ] || { echo 'FAIL: ran before 02:00 plus the install offset' >&2; exit 1; }
FAKE_DAY=2026-10-01 FAKE_HHMM=0237 FAKE_EPOCH=1790820060 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: did not run at 02:00 plus the install offset' >&2; exit 1; }
# Without a stored offset one is drawn once (0-59) and kept.
rm -f "$TMP/d2k/state/offset" "$TMP/attempt"
FAKE_DAY=2026-10-02 FAKE_HHMM=0100 FAKE_EPOCH=1790900000 run_tick
first=$(cat "$TMP/d2k/state/offset" 2>/dev/null || true)
case "$first" in ''|*[!0-9]*) echo "FAIL: no stored refresh offset ($first)" >&2; exit 1;; esac
[ "$first" -le 59 ] || { echo "FAIL: refresh offset out of range: $first" >&2; exit 1; }
FAKE_DAY=2026-10-02 FAKE_HHMM=0101 FAKE_EPOCH=1790900060 run_tick
[ "$(cat "$TMP/d2k/state/offset")" = "$first" ] || { echo 'FAIL: refresh offset is not stable' >&2; exit 1; }
printf 'junk\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-02 FAKE_HHMM=0102 FAKE_EPOCH=1790900120 run_tick
case "$(cat "$TMP/d2k/state/offset")" in ''|*[!0-9]*) echo 'FAIL: invalid offset was not replaced' >&2; exit 1;; esac
rm -f "$TMP/calls" "$TMP/attempt"; printf '08\n' > "$TMP/d2k/state/offset"
FAKE_DAY=2026-10-03 FAKE_HHMM=0208 FAKE_EPOCH=1791000000 run_tick
[ "$(cat "$TMP/calls" 2>/dev/null)" = 1 ] || { echo 'FAIL: offset 08 was not read as 8 minutes' >&2; exit 1; }
grep -q 'D2K_INSTAGRAM_REFRESH_AT' "$SCHEDULER" || { echo 'FAIL: explicit refresh time override is gone' >&2; exit 1; }
echo 'Instagram DNS scheduler: all checks passed'
