#!/bin/sh
# Run on the relay VPS with the static d2k-gate binary and its service file in
# the supplied directory. The gate holds no secrets.
set -eu
bundle=${1:?usage: install-server.sh BUNDLE_DIRECTORY}
[ "$(id -u)" = 0 ] || { echo 'root required' >&2; exit 1; }
install -m 0755 "$bundle/d2k-gate" /usr/local/bin/d2k-gate.new
mv /usr/local/bin/d2k-gate.new /usr/local/bin/d2k-gate
install -m 0644 "$bundle/d2k-gate.service" /etc/systemd/system/d2k-gate.service
systemctl daemon-reload
systemctl enable d2k-gate.service
systemctl restart d2k-gate.service
systemctl is-active d2k-gate.service
