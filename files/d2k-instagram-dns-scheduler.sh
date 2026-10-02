#!/bin/sh
# Local-time daily Instagram/WhatsApp DNS refresh after 02:00 router time plus
# a stable per-install offset of 0-59 minutes.
# Without any recorded success (fresh install, or the installer cleared it to
# pin a new host set) the first refresh runs right away, in the background of
# the service, so installation does not wait for slow edges.
# Cron is intentionally not used: Keenetic Entware cron does not reliably
# reload its crontab.
set -u
export PATH="${D2K_STUB_PATH:+$D2K_STUB_PATH:}/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin"

DIR=${D2K_DIR:-/opt/d2k}
HELPER=${D2K_INSTAGRAM_HELPER:-$DIR/d2k-instagram-dns.sh}
STATE=${D2K_INSTAGRAM_SCHED_STATE:-$DIR/state/instagram-dns-last-success}
ATTEMPT=${D2K_INSTAGRAM_SCHED_ATTEMPT:-/tmp/d2k-instagram-dns-last-attempt}
LOG=${D2K_INSTAGRAM_SCHED_LOG:-$DIR/log/instagram-dns-scheduler.log}
RUN_EVERY=${D2K_SCHEDULER_INTERVAL:-60}
RETRY_AFTER=${D2K_SCHEDULER_RETRY_AFTER:-1800}
OFFSET_FILE=${D2K_INSTAGRAM_SCHED_OFFSET:-$DIR/state/instagram-dns-offset}
# Explicit HHMM wins; otherwise 02:00 plus a per-install offset of 0-59
# minutes, drawn once and kept, so routers do not all call /resolve at once.
RUN_AT=${D2K_INSTAGRAM_REFRESH_AT:-}
child_pid=

stop_scheduler() {
    if [ -n "$child_pid" ]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    exit 0
}
trap stop_scheduler INT TERM HUP

log() {
    mkdir -p "$(dirname "$LOG")" 2>/dev/null || true
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG"
}

refresh_offset() {
    offset=$(cat "$OFFSET_FILE" 2>/dev/null || true)
    # Decimal only: a leading zero must not turn into octal for printf.
    case "$offset" in [0-9]|[1-5][0-9]) printf '%s\n' "$offset"; return 0;; 0[0-9]) printf '%s\n' "${offset#0}"; return 0;; esac
    offset=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
    case "$offset" in ''|*[!0-9]*) offset=$(awk -v s="$$" 'BEGIN{srand(s); print int(rand()*65536)}');; esac
    offset=$((offset % 60))
    mkdir -p "$(dirname "$OFFSET_FILE")" 2>/dev/null || true
    tmp="$OFFSET_FILE.new.$$"
    if printf '%s\n' "$offset" > "$tmp" && mv -f "$tmp" "$OFFSET_FILE"; then :; else rm -f "$tmp"; fi
    printf '%s\n' "$offset"
}

run_at() {
    if [ -n "$RUN_AT" ]; then printf '%s\n' "$RUN_AT"; return 0; fi
    printf '02%02d\n' "$(refresh_offset)"
}

tick() {
    today=$(date +%Y-%m-%d)
    hhmm=$(date +%H%M)
    at=$(run_at)
    if [ -e "$STATE" ]; then
        [ "$hhmm" -ge "$at" ] || return 0
    fi
    [ "$(cat "$STATE" 2>/dev/null || true)" != "$today" ] || return 0

    now=$(date +%s)
    last=$(cat "$ATTEMPT" 2>/dev/null || echo 0)
    case "$now:$last" in *[!0-9:]*) last=0;; esac
    [ "$last" -gt "$now" ] && last=0
    [ $((now - last)) -ge "$RETRY_AFTER" ] || return 0

    mkdir -p "$(dirname "$STATE")" "$(dirname "$ATTEMPT")" 2>/dev/null || true
    printf '%s\n' "$now" > "$ATTEMPT"
    log "обновление DNS Instagram/WhatsApp: старт"
    "$HELPER" refresh &
    child_pid=$!
    if wait "$child_pid"; then
        child_pid=
        tmp="$STATE.new.$$"
        if printf '%s\n' "$today" > "$tmp" && mv -f "$tmp" "$STATE"; then
            log "DNS Instagram/WhatsApp обновлён; следующий запуск после $at завтра"
        else
            rm -f "$tmp"
            log 'обновление успешно, но не удалось сохранить дату; временной backoff не даст запускать повтор каждую минуту'
        fi
    else
        rc=$?
        child_pid=
        log "VPS не ответил или не прошёл проверку (код $rc); повтор через ${RETRY_AFTER} секунд, текущие записи сохранены"
    fi
}

case "${1:-run}" in
    tick) tick ;;
    run)
        while :; do
            tick
            sleep "$RUN_EVERY"
        done
        ;;
    *) echo "usage: $0 {run|tick}" >&2; exit 2 ;;
esac
