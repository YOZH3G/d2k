#!/bin/sh
# Run one CI shard of `make -C core san` (ASan + UBSan).
#
# One serial run took 22.4 minutes in CI on 12.10.2026, and 21.5 of them were
# the test loop. Measured from that log:
#
#   test_sched      6.8 min
#   test_compose    3.2 min
#   ~46 others      ~11.5 min together
#   extra targets   0.9 min  (san-measured, san-probe-plan, san-mips-pipe, ...)
#
# Shards: sched | compose (+ every extra target) | rest-1 | rest-2. The two
# rest shards take every other test of what remains, so they come out even.
#
# The test list comes from `make san-list` and the extra targets from make's
# own database, so a shard cannot silently drop what `make san` would run.
# `verify` fails unless the shards cover the loop exactly.
#
# Usage: ci-core-san-shard.sh sched|compose|rest-1|rest-2|verify
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HEAVY="test_sched test_compose"

loop_tests() { make -s -C "$ROOT/core" san-list | tr -s ' ' '\n' | grep -v '^$'; }

rest_tests() {
    all=$(loop_tests)
    for h in $HEAVY; do
        printf '%s\n' "$all" | grep -qxF "$h" \
            || { echo "ci-core-san-shard: '$h' is no longer in the loop; update HEAVY" >&2; exit 1; }
    done
    printf '%s\n' "$all" | grep -vxF -e test_sched -e test_compose
}

# Every prerequisite of `san` except the loop itself: the extra san-* targets.
extra_targets() {
    make -C "$ROOT/core" -pRrq san 2>/dev/null \
        | sed -n 's/^san://p' \
        | awk '{ if (NF > n) { n = NF; line = $0 } } END { print line }' \
        | tr -s ' \t' '\n' | grep -v '^$' | grep -vxF san-loop
}

half() { rest_tests | awk -v k="$1" 'NR % 2 == k'; }

shard=${1:-}
case "$shard" in
    sched)   tests="test_sched";   extras="" ;;
    compose) tests="test_compose"; extras=$(extra_targets) ;;
    rest-1)  tests=$(half 1);      extras="" ;;
    rest-2)  tests=$(half 0);      extras="" ;;
    verify)
        all=$(loop_tests | sort)
        # shellcheck disable=SC2086 # HEAVY is a word list on purpose
        union=$( { printf '%s\n' $HEAVY; half 1; half 0; } | sort)
        if [ "$all" != "$union" ]; then
            echo "ci-core-san-shard: shards do not cover the san loop exactly" >&2
            exit 1
        fi
        echo "ci-core-san-shard: $(printf '%s\n' "$all" | wc -l | tr -d ' ') tests, shards cover all of them"
        exit 0
        ;;
    *)
        echo "usage: $0 sched|compose|rest-1|rest-2|verify" >&2
        exit 2
        ;;
esac

# shellcheck disable=SC2086 # word lists on purpose
echo "ci-core-san-shard $shard: tests: $(printf '%s ' $tests)"
# shellcheck disable=SC2086
make -C "$ROOT/core" san-loop SAN_TESTS="$(printf '%s ' $tests)"
if [ -n "$extras" ]; then
    # shellcheck disable=SC2086
    echo "ci-core-san-shard $shard: extra targets: $(printf '%s ' $extras)"
    # shellcheck disable=SC2086
    make -C "$ROOT/core" $extras
fi
