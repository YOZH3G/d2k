#!/bin/sh
# d2kfetch-record.sh OUT NAME IP PATH TAG — preserve probe stdout/stderr/status.
# JSON is decoded by router-round-report.py on the host, not by router sed/awk.
# D2KFETCH may select an explicitly versioned diagnostic binary.
set -u
out=$1 name=$2 ip=$3 path=$4 tag=$5
case "$name" in ''|*[!a-zA-Z0-9._-]*) echo 'invalid target name' >&2; exit 2;; esac
case "$tag" in learn|control|late) ;; *) echo 'invalid tag' >&2; exit 2;; esac
file=$(mktemp "$out/probe.XXXXXX") || exit 2
"${D2KFETCH:-/opt/sbin/d2kfetch}" --name "$name" --ip "$ip" --path "$path" \
    --quic --deadline 15000 --json > "$file" 2> "$file.err"
rc=$?
printf '%s %s {"name":"%s","mode":"h3","instrument":"d2kfetch","rc":%d,"probe_file":"%s"}\n' \
    "$(date +%T)" "$tag" "$name" "$rc" "${file##*/}" >> "$out/$tag.jsonl"
