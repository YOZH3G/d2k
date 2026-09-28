#!/bin/sh
# Local-time daily Instagram DNS refresh. Cron is intentionally not used:
# Keenetic Entware cron does not reliably reload its crontab.
set -u
export PATH="${D2K_STUB_PATH:+$D2K_STUB_PATH:}/opt/sbin:/opt/bin:/sbin:/usr/sbin:/bin:/usr/bin"

DIR=${D2K_DIR:-/opt/d2k}
HELPER=${D2K_INSTAGRAM_HELPER:-$DIR/d2k-instagram-dns.sh}
STATE=${D2K_INSTAGRAM_SCHED_STATE:-$DIR/state/instagram-dns-last-success}
ATTEMPT=${D2K_INSTAGRAM_SCHED_ATTEMPT:-/tmp/d2k-instagram-dns-last-attempt}
LOG=${D2K_INSTAGRAM_SCHED_LOG:-$DIR/log/instagram-dns-scheduler.log}
RUN_EVERY=${D2K_SCHEDULER_INTERVAL:-60}
RETRY_AFTER=${D2K_SCHEDULER_RETRY_AFTER:-1800}
RUN_AT=${D2K_INSTAGRAM_REFRESH_AT:-0400}
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

tick() {
    today=$(date +%Y-%m-%d)
    hhmm=$(date +%H%M)
    [ "$hhmm" -ge "$RUN_AT" ] || return 0
    [ "$(cat "$STATE" 2>/dev/null || true)" != "$today" ] || return 0

    now=$(date +%s)
    last=$(cat "$ATTEMPT" 2>/dev/null || echo 0)
    case "$now:$last" in *[!0-9:]*) last=0;; esac
    [ "$last" -gt "$now" ] && last=0
    [ $((now - last)) -ge "$RETRY_AFTER" ] || return 0

    mkdir -p "$(dirname "$STATE")" "$(dirname "$ATTEMPT")" 2>/dev/null || true
    printf '%s\n' "$now" > "$ATTEMPT"
    log "ночное обновление Instagram DNS: старт"
    "$HELPER" refresh &
    child_pid=$!
    if wait "$child_pid"; then
        child_pid=
        tmp="$STATE.new.$$"
        if printf '%s\n' "$today" > "$tmp" && mv -f "$tmp" "$STATE"; then
            log "Instagram DNS обновлён; следующий запуск после $RUN_AT завтра"
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
