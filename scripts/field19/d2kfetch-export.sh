#!/bin/sh
# Exact byte framing: NAME SIZE\n followed by SIZE bytes. No tar/base64 needed.
# Files are read only after all probes have exited. An empty directory is valid.
set -eu
cd "${1:?probe directory}"
for f in probe.*; do
    [ -f "$f" ] || continue
    case "$f" in *[!a-zA-Z0-9._-]*) exit 2;; esac
    n=$(wc -c < "$f")
    printf '%s %s\n' "$f" "$n"
    cat "$f"
done
printf 'DONE\n'
