#!/bin/sh
# running() в S99d2k: зомби — мёртвый процесс. Демоны, запущенные обновлятором,
# усыновляет его супервизор; пока он не собрал завершившегося потомка, тот
# висит зомби. Считать его живым значило ждать, добивать KILL и объявлять
# остановку сорванной (лаборатория 05.10.2026: перезапуск Telegram сторожем
# во время передачи работы обновлятору оставлял туннель лежать).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }

awk '/^running\(\) \{/,/^\}/' "$ROOT/files/S99d2k" > "$TMP/running.sh"
[ -s "$TMP/running.sh" ] || fail "running() not found in S99d2k"
# shellcheck disable=SC1091
. "$TMP/running.sh"
PROC_DIR=$TMP/proc

mkdir -p "$PROC_DIR/101" "$PROC_DIR/102" "$PROC_DIR/103"
echo '101 (d2ktg) S 1 101 101 0 -1' > "$PROC_DIR/101/stat"
echo '102 (d2ktg) Z 1 102 102 0 -1' > "$PROC_DIR/102/stat"
echo '103 (a) b) Z 1 103 103 0 -1' > "$PROC_DIR/103/stat"
for n in 101 102 103 104; do echo "$n" > "$TMP/$n.pid"; done

running "$TMP/101.pid" || fail "sleeping process must be running"
if running "$TMP/102.pid"; then fail "zombie must not count as running"; fi
if running "$TMP/103.pid"; then fail "zombie with ') ' in its name must not count as running"; fi
if running "$TMP/104.pid"; then fail "absent process must not count as running"; fi
if running "$TMP/none.pid"; then fail "missing pidfile must not count as running"; fi
echo "S99 running(): zombies and absent processes are not running: PASS"
