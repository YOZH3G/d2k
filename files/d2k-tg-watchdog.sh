#!/bin/sh
# Active health probe for the TCP Telegram relay. Three failures avoid flapping.
set -u
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

DIR=${D2K_DIR:-/opt/d2k}
INIT=/opt/etc/init.d/S99d2k
STATE=$DIR/state/telegram-health.failures
PROBE_URL=https://core.telegram.org/
# Telegram's HTTPS endpoint, as in z2k. A native MTProto DC does not speak
# HTTPS and would trigger periodic restarts of a healthy tunnel.
PROBE_IP=149.154.167.99

failures=0
tick() {
    if [ -L "$DIR/current" ]; then
        if [ "${D2K_MANAGED_INTERNAL:-}" != 1 ]; then
            "$DIR/boot/d2k-service-adapter" --root "$DIR" service tg-tick
            return $?
        fi
        "$DIR/boot/d2k-service-adapter" --root "$DIR" --validate-maintenance-fd 4 || return 1
        failures=$(cat "$STATE" 2>/dev/null || echo 0)
        case "$failures" in ''|*[!0-9]*) failures=0;; esac
    fi
    [ -x "${D2K_RELEASE_ROOT:-$DIR}/d2k-tg-firewall.sh" ] && "${D2K_RELEASE_ROOT:-$DIR}/d2k-tg-firewall.sh" heal >/dev/null 2>&1 || true
    if curl --connect-timeout 8 --max-time 15 -sf -o /dev/null \
        --resolve "core.telegram.org:443:$PROBE_IP" "$PROBE_URL" 2>/dev/null; then
        failures=0
        rm -f "$STATE"
    else
        failures=$((failures + 1))
        echo "$failures" > "$STATE"
        if [ "$failures" -ge 3 ]; then
            if [ "${D2K_MANAGED_INTERNAL:-}" = 1 ]; then
                "$D2K_RELEASE_ROOT/S99d2k" --managed telegram-restart 8 >/dev/null 2>&1 || true
            else
                "$INIT" telegram-restart >/dev/null 2>&1 || true
            fi
            failures=0
            rm -f "$STATE"
        fi
    fi
}
case "${1:-run}" in
    tick) tick ;;
    run) while :; do tick; sleep 60; done ;;
    *) exit 2 ;;
esac
