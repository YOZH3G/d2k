#!/bin/sh
# shellcheck disable=SC2013  # word lists (names, faces), not lines
# Static check that the install chain carries every file the service needs:
#   1. every $DIR/... file and /opt/sbin/d2k* binary named by files/S99d2k or
#      a runtime helper in files/ is installed by scripts/install.sh;
#   2. every repository path install.sh fetches is staged by
#      scripts/lab-install.sh (whose D2K_LOCAL install dies on the first
#      missing file, before it installs anything);
#   3. every helper install.sh puts in $DIR is removed by scripts/uninstall.sh.
# Runtime directories and state written by the service itself are excluded.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL=$ROOT/scripts/install.sh
LAB=$ROOT/scripts/lab-install.sh
UNINSTALL=$ROOT/scripts/uninstall.sh
fail() { echo "FAIL: $*" >&2; exit 1; }

# shellcheck disable=SC2016  # literal $DIR as written in the scripts
refs=$(grep -oh '\$DIR/[A-Za-z0-9._/-]*' "$ROOT/files/S99d2k" "$ROOT"/files/*.sh | sort -u |
    grep -vE '^\$DIR/(config|log|run|state|panel)(/|$)')
[ -n "$refs" ] || fail "no runtime file references found (layout changed?)"
for ref in $refs; do
    name=${ref#\$DIR/}
    grep -qF "\"\$DIR/$name\"" "$INSTALL" || fail "install.sh does not install $ref (named by the runtime)"
done
for bin in $(grep -oh '/opt/sbin/d2k[a-z]*' "$ROOT/files/S99d2k" "$ROOT"/files/*.sh | sort -u); do
    name=${bin#/opt/sbin/}
    grep -qF "\"\$SBIN/$name\"" "$INSTALL" || fail "install.sh does not install $bin"
done
echo "PASS: install.sh installs every file and binary the service references"

fetched=$(sed -n 's/^fetch "\([^"]*\)".*/\1/p' "$INSTALL")
[ -n "$fetched" ] || fail "no fetch lines in install.sh (layout changed?)"
for path in $fetched; do
    case "$path" in
        builds/*-linux-\$ARCH)
            bin=${path#builds/}; bin=${bin%-linux-\$ARCH}
            grep -qF "\$REL/builds/$bin-linux-\$ARCH" "$LAB" || fail "lab-install.sh does not stage $path" ;;
        *) grep -qF "$path" "$LAB" || fail "lab-install.sh does not stage $path" ;;
    esac
done
# Fonts are fetched in a loop over faces.
for face in $(sed -n 's/^for face in \(.*\); do$/\1/p' "$INSTALL"); do
    grep -qF "fonts/$face.woff2" "$LAB" || fail "lab-install.sh does not stage font $face"
done
grep -q 'install.sh fetch' "$LAB" || fail "lab-install.sh lacks its own staged-file preflight"
echo "PASS: lab-install.sh stages every file install.sh fetches"

# shellcheck disable=SC2016
for name in $(sed -n 's/^install_atomic "\$TMP\/[^"]*" "\$DIR\/\([^"]*\.sh\)"$/\1/p' "$INSTALL"); do
    grep -qF "\$DIR/$name" "$UNINSTALL" || fail "uninstall.sh does not remove \$DIR/$name"
done
echo "PASS: uninstall.sh removes every installed helper"
echo "install manifest: all checks passed"
