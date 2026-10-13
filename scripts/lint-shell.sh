#!/bin/sh
# Lint every shell script D2K ships or runs, with shellcheck. One list for CI and
# scripts/check.sh: two hand-kept lists drifted apart once already — CI did not
# lint files/S99d2k at all, the script that installs the router's firewall.
#
# *.sh files are found by glob. The init and service scripts in files/ have no
# extension by convention (S99d2k, d2k-openwrt-init), so the glob misses them:
# every file in files/ that starts with a shebang for sh is linted too.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

list=$(mktemp)
trap 'rm -f "$list"' EXIT

find scripts files spike -type f -name '*.sh' > "$list"
for f in files/*; do
    [ -f "$f" ] || continue
    case "$f" in *.sh) continue ;; esac
    head -n 1 "$f" | grep -qE '^#!(/usr)?/bin/(env )?sh' && echo "$f" >> "$list"
done

n=$(wc -l < "$list" | tr -d ' ')
# shellcheck disable=SC2046 # the list holds plain repository paths
shellcheck -s sh $(sort -u "$list")
echo "lint-shell: $n files clean"
