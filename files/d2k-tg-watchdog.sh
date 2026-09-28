#!/bin/sh
# Active health probe for the TCP Telegram relay. Three failures avoid flapping.
set -u
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

DIR=/opt/d2k
INIT=/opt/etc/init.d/S99d2k
STATE=$DIR/state/telegram-health.failures
PROBE_URL=https://core.telegram.org/
PROBE_IP=149.154.167.51

failures=0
while :; do
    [ -x "$DIR/d2k-tg-firewall.sh" ] && "$DIR/d2k-tg-firewall.sh" heal >/dev/null 2>&1 || true
    if curl --connect-timeout 8 --max-time 15 -sf -o /dev/null \
        --resolve "core.telegram.org:443:$PROBE_IP" "$PROBE_URL" 2>/dev/null; then
        failures=0
        rm -f "$STATE"
    else
        failures=$((failures + 1))
        echo "$failures" > "$STATE"
        if [ "$failures" -ge 3 ]; then
            "$INIT" telegram-restart >/dev/null 2>&1 || true
            failures=0
            rm -f "$STATE"
        fi
    fi
    sleep 60
done
