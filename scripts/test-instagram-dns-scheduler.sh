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
        D2K_INSTAGRAM_SCHED_LOG="$TMP/scheduler.log" HELPER_CALLS="$TMP/calls" \
        D2K_SCHEDULER_RETRY_AFTER=1800 sh "$SCHEDULER" tick
}

# A previous day's success: wait for 02:00 router time.
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
grep -q 'D2K_INSTAGRAM_REFRESH_AT:-0200' "$SCHEDULER" || { echo 'FAIL: default refresh time is not 02:00' >&2; exit 1; }
echo 'Instagram DNS scheduler: all checks passed'
