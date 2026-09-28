#!/bin/sh
# Execute the two documented one-liners with a controlled download boundary.
# A failed/partial download must never execute; temp scripts must be removed.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir "$WORK/bin"
export RUN_MARKER="$WORK/executed" CURL_TARGET="$WORK/target" CURL_URL="$WORK/url"
cat > "$WORK/bin/curl" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) shift; target=$1 ;;
        https://*) printf '%s\n' "$1" > "$CURL_URL" ;;
    esac
    shift
done
printf '%s\n' "$target" > "$CURL_TARGET"
printf 'printf "executed:%%s\\n" "${D2K_REF:-unset}" >> "$RUN_MARKER"\n' > "$target"
[ "${DOWNLOAD_FAIL:-0}" = 0 ] || exit 22
EOF
chmod +x "$WORK/bin/curl"
export PATH="$WORK/bin:$PATH"
for n in 1 2; do
    command=$(awk -v wanted="$n" '/^```sh$/ {block++; if(block==wanted){getline; print; exit}}' "$ROOT/README.md")
    [ -n "$command" ] || { echo 'missing documented command' >&2; exit 1; }
    sh -n -c "$command"
    rm -f "$RUN_MARKER"
    if DOWNLOAD_FAIL=1 sh -c "$command"; then echo 'failed download returned success' >&2; exit 1; fi
    [ ! -e "$RUN_MARKER" ] || { echo 'partial download was executed' >&2; exit 1; }
    [ ! -e "$(cat "$CURL_TARGET")" ] || { echo 'failed download leaked temp file' >&2; exit 1; }
    DOWNLOAD_FAIL=0 sh -c "$command"
    [ -s "$RUN_MARKER" ]
    [ ! -e "$(cat "$CURL_TARGET")" ]
    if [ "$n" = 1 ]; then
        [ "$(cat "$RUN_MARKER")" = executed:feat/telegram-tunnel ]
        [ "$(cat "$CURL_URL")" = https://raw.githubusercontent.com/necronicle/d2k/feat/telegram-tunnel/scripts/install.sh ]
    else
        [ "$(cat "$CURL_URL")" = https://raw.githubusercontent.com/necronicle/d2k/feat/telegram-tunnel/scripts/uninstall.sh ]
    fi
done
echo 'README install/uninstall: execution, failed-download safety and cleanup passed'
