#!/bin/sh
# hello-shape-probe.sh — выполняется НА РОУТЕРЕ. Один подтверждённый TCP-план,
# по N запросов тремя приветствиями (Chrome 150 с ECH-GREASE, Chrome 150 без
# ECH, Safari 26) к одной цели; tcpdump первых сегментов на ppp0, pcap
# приветствий и коды curl. Вопрос: применяется ли план к приветствию, не
# влезающему в один сегмент. Отчёт на маке — hello-shape-report.py.
# Аргументы: цель [N] [режимы через запятую]; результаты в /tmp/hs-<цель>/
set -u
T=${1:?target}; N=${2:-6}; MODES=$(echo "${3:-chrome-ech,chrome,safari}" | tr , " ")
OUT=/tmp/hs-$T; rm -rf "$OUT"; mkdir -p "$OUT"
C=/opt/d2k-tools/curl-impersonate; CA=/opt/d2k-tools/cacert.pem
IP=$($C -s -m 8 --cacert "$CA" -H 'accept: application/dns-json' \
    "https://1.1.1.1/dns-query?name=$T&type=A" | tr ',' '\n' | \
    sed -n 's/.*"data":"\([0-9.]*\)".*/\1/p' | head -1)
[ -n "$IP" ] || { echo "no ip"; exit 4; }
echo "$IP" > "$OUT/ip"; date +%T > "$OUT/t0"
tcpdump -i ppp0 -n -l -tt "tcp and host $IP and port 443" > "$OUT/tcpdump.txt" 2> "$OUT/tcpdump.err" &
TP0=$!
tcpdump -i ppp0 -n -s 0 -w "$OUT/hello.pcap" "tcp and host $IP and port 443" 2>/dev/null &
TP=$!; sleep 1
for mode in $MODES; do
    case $mode in
        chrome-ech) set -- --impersonate chrome150 --ech true ;;
        chrome)     set -- --impersonate chrome150 ;;
        safari)     set -- --impersonate safari260 ;;
        *) echo "unknown mode $mode"; continue ;;
    esac
    i=0
    while [ "$i" -lt "$N" ]; do i=$((i+1))
        r=$($C -4 -s -o /dev/null --cacert "$CA" -m 20 --resolve "$T:443:$IP" "$@" \
            -w '%{http_code} %{size_download} %{time_total} lport=%{local_port}' "https://$T/" 2>/dev/null); rc=$?
        echo "$(date +%T) $mode $i rc=$rc $r" >> "$OUT/fetch.txt"
        sleep 2
    done
done
sleep 2; kill "$TP" "$TP0" 2>/dev/null; wait "$TP" "$TP0" 2>/dev/null
date +%T > "$OUT/t1"
echo "done $OUT"
