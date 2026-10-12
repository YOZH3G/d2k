#!/bin/sh
# Run one CI shard of `make -C core check`.
#
# Why shards. One serial `make -C core check` took 18.8 minutes in CI. The time
# is not spread evenly; measured from the CI log of 12.10.2026:
#
#   test-sched          6.4 min   (the full scheduler run)
#   test-sched-modes    ~5  min   (13 modes; each covers what the full run
#                                  does not — --groups-only once stayed red
#                                  for a month while check skipped it)
#   test-compose        3.0 min
#   test-measured       1.6 min
#   everything else     ~2.8 min  (about 60 small targets)
#
# Each heavy target gets its own job; the rest share one. Wall time then
# follows the slowest shard (~6.5 min), not the sum.
#
# The target list comes from make's own database, not from grep: grep missed
# two prerequisites (check-release, cross-mips-pipe) that make does see. A
# shard therefore cannot silently drop a test that check would run.
#
# Usage: ci-core-shard.sh sched|sched-modes|compose-measured|rest|verify
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HEAVY="test-sched test-sched-modes test-compose test-measured"

all_targets() {
    make -C "$ROOT/core" -pRrq check 2>/dev/null \
        | sed -n 's/^check://p' \
        | awk '{ if (NF > n) { n = NF; line = $0 } } END { print line }' \
        | tr -s ' \t' '\n' | grep -v '^$' | sort -u
}

rest_targets() {
    all=$(all_targets)
    for h in $HEAVY; do
        printf '%s\n' "$all" | grep -qxF "$h" \
            || { echo "ci-core-shard: '$h' is no longer in check; update HEAVY" >&2; exit 1; }
    done
    filter=''
    for h in $HEAVY; do filter="$filter -e $h"; done
    # shellcheck disable=SC2086
    printf '%s\n' "$all" | grep -vxF $filter
}

shard=${1:-}
case "$shard" in
    sched)            targets="test-sched" ;;
    sched-modes)      targets="test-sched-modes" ;;
    compose-measured) targets="test-compose test-measured" ;;
    rest)             targets=$(rest_targets) ;;
    verify)
        # The union of all shards must equal check exactly.
        all=$(all_targets)
        # shellcheck disable=SC2086 # HEAVY is a word list on purpose
        union=$( { printf '%s\n' $HEAVY; rest_targets; } | sort -u)
        if [ "$all" != "$union" ]; then
            echo "ci-core-shard: shards do not cover check exactly" >&2
            exit 1
        fi
        echo "ci-core-shard: $(printf '%s\n' "$all" | wc -l | tr -d ' ') targets, shards cover all of them"
        exit 0
        ;;
    *)
        echo "usage: $0 sched|sched-modes|compose-measured|rest|verify" >&2
        exit 2
        ;;
esac

# shellcheck disable=SC2086 # targets is a word list on purpose
echo "ci-core-shard $shard: $(printf '%s ' $targets)"
# shellcheck disable=SC2086
make -C "$ROOT/core" $targets
