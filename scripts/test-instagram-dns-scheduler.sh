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

run_tick
[ ! -e "$TMP/calls" ] || { echo 'FAIL: ran before 04:00 local time' >&2; exit 1; }
FAKE_HHMM=0400 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: did not run at 04:00' >&2; exit 1; }
FAKE_HHMM=0410 FAKE_EPOCH=1790654940 run_tick
[ "$(cat "$TMP/calls")" = 1 ] || { echo 'FAIL: retried before backoff expired' >&2; exit 1; }
FAKE_HHMM=0431 FAKE_EPOCH=1790656200 run_tick
[ "$(cat "$TMP/calls")" = 2 ] || { echo 'FAIL: did not retry after resolver failure' >&2; exit 1; }
[ "$(cat "$TMP/d2k/state/success")" = 2026-09-29 ] || { echo 'FAIL: successful date not persisted' >&2; exit 1; }
FAKE_HHMM=0500 FAKE_EPOCH=1790657940 run_tick
[ "$(cat "$TMP/calls")" = 2 ] || { echo 'FAIL: refreshed more than once after success' >&2; exit 1; }
echo 'Instagram DNS scheduler: all checks passed'
