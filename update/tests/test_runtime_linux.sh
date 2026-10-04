#!/bin/sh
# Isolated container smoke only: no router, no firewall changes, no external network.
# Args: unpacked artifacts directory containing runtime-linux/, files/, test binaries.
set -eu
artifacts=${1:?artifacts directory}
"$artifacts/test_health-linux-arm64"
"$artifacts/test_health_local-linux-arm64"
for binary in "$artifacts/runtime-linux/d2kd-linux-arm64" "$artifacts/runtime-linux/d2ktg-linux-arm64"; do
    [ "$("$binary" --release-id)" = dev ]
    "$binary" --self-check
    "$binary" --version
 done
work=$(mktemp -d /tmp/d2ku-tg-XXXXXX)
pid=
cleanup() { if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi; rm -rf "$work"; }
trap cleanup EXIT INT TERM
cat > "$work/config" <<CONFIG
TG_ENABLED=1
TG_RELAY_URL=wss://127.0.0.1:1/ws
TG_RELAY_SECRET=fixture-secret
TG_CA_BUNDLE=$artifacts/files/tg-roots.pem
TG_IDENTITY=$work/identity
TG_STATUS=$work/status
TG_PORT=1443
CONFIG
"$artifacts/runtime-linux/d2ktg-linux-arm64" --config "$work/config" --health-file "$work/health" > "$work/log" 2>&1 &
pid=$!
sleep 2
if [ ! -s "$work/health" ]; then cat "$work/log"; exit 1; fi
read magic actual_pid start mono boot release wire peer connected ready external < "$work/health"
[ "$magic" = D2KH1 ] && [ "$actual_pid" = "$pid" ] && [ "$start" -gt 0 ]
[ "$ready" = 1 ] && [ "$external" = 0 ] && [ "$release" = dev ] && [ "$wire" = 13 ]
first_mono=$mono
sleep 2
read magic actual_pid start mono boot release wire peer connected ready external < "$work/health"
[ "$mono" -gt "$first_mono" ] && [ "$ready" = 1 ] && [ "$external" = 0 ]
kill "$pid"; wait "$pid"; pid=
printf '%s\n' 'Telegram local listener remains healthy through external relay failure: PASS'
