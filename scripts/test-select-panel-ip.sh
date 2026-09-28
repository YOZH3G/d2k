#!/bin/sh
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

selected=$(cat <<'ADDRS' | sh "$HERE/select-panel-ip.sh"
9: ezcfg0 inet 198.51.100.11/32 scope global ezcfg0
33: br1 inet 10.1.30.1/24 scope global br1
34: br0 inet 192.168.1.1/24 brd 192.168.1.255 scope global br0
37: ppp0 inet 88.87.93.11 peer 178.78.39.254/32 scope global ppp0
ADDRS
)
[ "$selected" = "192.168.1.1" ] || {
    echo "expected primary br0 address, got: $selected" >&2
    exit 1
}

selected=$(printf '%s\n' \
    '1: ppp0 inet 88.87.93.11/32 scope global ppp0' \
    '2: eth0 inet 10.23.0.1/24 scope global eth0' |
    sh "$HERE/select-panel-ip.sh")
[ "$selected" = "10.23.0.1" ] || {
    echo "expected private-address fallback, got: $selected" >&2
    exit 1
}

selected=$(printf '%s\n' \
    '1: ppp0 inet 88.87.93.11/32 scope global ppp0' |
    sh "$HERE/select-panel-ip.sh")
[ -z "$selected" ] || {
    echo "expected no public bind address, got: $selected" >&2
    exit 1
}

echo "LAN panel address selection passed"
