#!/bin/sh
# router-round.sh <label> : прогон поля ЦЕЛИКОМ с роутера, без браузеров (решение
# владельца 17.10.2026). Чистый каталог, затем curl-impersonate по каждой цели: обучающие
# запросы в t0, t0+60, t0+120 с, контрольный — через WAIT с от t0. Итог по каждой
# цели и входа: код curl (0 — ответ полный), HTTP-код, размер, протокол; плюс
# журнал d2kc за прогон.
#   EXPECT=<release-id> — остановиться, если на роутере другая сборка.
#   EXPECT_FETCH=<release-id> — версия прибора (по умолчанию EXPECT).
#   D2KFETCH=<path>      — отдельный диагностический бинарь на роутере.
#   Diagnostic build: make -C core fetch-release RELEASE_ID=<id>;
#   copy builds/d2kfetch-linux-arm64 and set D2KFETCH/EXPECT_FETCH to that id.
#   WAIT=<s>            — от t0 до контроля (по умолчанию 240).
#   CLEAR=0             — каталог не чистить.
# Инструмент: /opt/d2k-tools/curl-impersonate (Chrome 150 с ECH, Safari 26, HTTP/3).
# Подресурсы страниц не грузятся — ключевые ресурсы перечислены отдельными целями.
set -u
L=${1:?run label}
case "$L" in *[!a-zA-Z0-9._-]*|''|.|..) echo "invalid label" >&2; exit 4;; esac
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L; rm -rf "$R"; mkdir -p "$R"
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=10 -p 222 root@192.168.1.1"
W=${WAIT:-240}
FETCH=${D2KFETCH:-/opt/sbin/d2kfetch}
case "$FETCH" in *[!a-zA-Z0-9/._-]*|'') echo "invalid D2KFETCH path"; exit 4;; esac
FV=$($SSH "$FETCH --version") || { echo "round-stopped $L: не удалось получить версию $FETCH" >&2; exit 4; }
FE=${EXPECT_FETCH:-${EXPECT:-}}
if [ -n "$FE" ] && [ "$FV" != "d2kfetch $FE" ]; then
    echo "round-stopped $L: прибор $FV, ожидался d2kfetch $FE"; exit 4
fi
printf '%s\n' "$FV" > "$R/instrument.txt"
$SSH "sha256sum $FETCH" >> "$R/instrument.txt" || exit 4
RID=$($SSH "cat /opt/d2k/release-id")
if [ -n "${EXPECT:-}" ] && [ "$RID" != "$EXPECT" ]; then
    echo "round-stopped $L: на роутере $RID, ожидалась $EXPECT"; exit 4
fi
# цель|входы|путь   входы: chrome (Chrome 150, ECH если есть в HTTPS RR),
# safari (Safari 26, без ECH), h3 (HTTP/3 — свой d2kfetch --quic: HTTP/3 curl-impersonate
# на ядре 4.9 роутера не отправляет), http (открытый HTTP)
TARGETS='rutracker.org|chrome,safari,h3|/
fost.club|chrome,safari,h3|/
nnmclub.to|chrome,safari,h3|/
www.fast-torrent.ru|http|/
media5.cdnbase.com|http|/media/theme/fast.5.css
lostfilm.tv|chrome,safari,h3|/
kinozal.me|chrome,safari,h3|/
bible-center.ru|chrome,safari|/
ru.numista.com|chrome,safari|/
rua.gr|chrome,safari,h3|/
enimerosi.com|chrome,safari,h3|/
cdnb.enimerosi.com|chrome,safari|/photos/katsaitis1686837855.jpg?crop=240,240
romfea.gr|chrome,safari,h3|/
katzauction.com|chrome,safari,h3|/
spzh.eu|chrome,safari,h3|/ru/
flibusta.is|chrome,safari|/
web.facebook.com|chrome,safari,h3|/
static.xx.fbcdn.net|chrome,safari|/rsrc.php/v5/y6/l/0,cross/4beuxQDwe0W.css
adguard.com|chrome,safari,h3|/
mailsuite.com|chrome,safari|/
www.cloudflare.com|chrome,safari,h3|/
speed.cloudflare.com|chrome,safari,h3|/'
printf '%s\n' "$TARGETS" > "$R/targets.txt"
# Сценарий на роутере: каждая цель в своём фоне, запросы по расписанию.
cat > "$R/round-router.sh" <<EOF
#!/bin/sh
OUT=/tmp/rr-$L; rm -rf \$OUT; mkdir -p \$OUT
[ "${CLEAR:-1}" = 0 ] || /opt/etc/init.d/S99d2k clear-found >/dev/null 2>&1
sleep 5
date +%T > \$OUT/t0; T0=\$(date +%s)
fetch() { # host mode path tag
    m=\$2
        C="/opt/d2k-tools/curl-impersonate -4 -s -o /dev/null --cacert /opt/d2k-tools/cacert.pem --compressed -m 20 --doh-url https://1.1.1.1/dns-query"
        case \$m in
            chrome) a="--impersonate chrome150 --ech true"; u="https://\$1\$3" ;;
            safari) a="--impersonate safari260"; u="https://\$1\$3" ;;
            h3) a="--impersonate chrome150 --http3-only"; u="https://\$1\$3" ;;
            http) a="--impersonate chrome150 --http1.1"; u="http://\$1\$3" ;;
        esac
        if [ "\$m" = h3 ]; then
            # HTTP/3 curl-impersonate на ядре роутера не отправляет — свой d2kfetch;
            # адрес — тем же DoH, что у curl (DNS роутера может отдать чужой прокси).
            ip=\$(/opt/d2k-tools/curl-impersonate -s -m 8 --cacert /opt/d2k-tools/cacert.pem -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=\$1&type=A" | tr ',' '\n' | sed -n 's/.*"data":"\([0-9.]*\)".*/\1/p' | head -1)
            D2KFETCH="${D2KFETCH:-/opt/sbin/d2kfetch}" sh /tmp/rr-$L.record "\$OUT" "\$1" "\$ip" "\$3" "\$4"
            return
        else
            r=\$(\$C \$a -w '"code":%{http_code},"ver":"%{http_version}","size":%{size_download},"t":%{time_total},"ip":"%{remote_ip}","loc":"%{redirect_url}"' "\$u" 2>/dev/null); rc=\$?
        fi
        echo "\$(date +%T) \$4 {\"name\":\"\$1\",\"mode\":\"\$m\",\"rc\":\$rc,\$r}" >> \$OUT/\$4.jsonl
}
at() { now=\$(date +%s); d=\$((T0 + \$1 - now)); [ \$d -gt 0 ] && sleep \$d; }
trap '' HUP
i=0
while IFS='|' read -r h ms p; do
    [ -n "\$h" ] || continue
    for m in \$(echo "\$ms" | tr , ' '); do
        o=\$((i % 15)); i=\$((i + 1))
        ( at \$o; fetch "\$h" "\$m" "\$p" learn; at \$((60 + o)); fetch "\$h" "\$m" "\$p" learn;
          at \$((120 + o)); fetch "\$h" "\$m" "\$p" learn; at \$(($W + o)); fetch "\$h" "\$m" "\$p" control ) &
    done
done < /tmp/rr-$L.targets
wait
date +%T > \$OUT/t1
EOF
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.record" < "$(dirname "$0")/d2kfetch-record.sh" || exit 4
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.targets" < "$R/targets.txt" || exit 4
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.sh" < "$R/round-router.sh" || exit 4
transfer_rc=0
$SSH "sh /tmp/rr-$L.sh" || transfer_rc=4
$SSH "cat /tmp/rr-$L/t0" > "$R/t0.txt" || transfer_rc=4
echo "$RID" >> "$R/t0.txt"
$SSH "cat /tmp/rr-$L/learn.jsonl" > "$R/learn.jsonl" || transfer_rc=4
$SSH "cat /tmp/rr-$L/control.jsonl" > "$R/control.jsonl" || transfer_rc=4
# One transfer preserves raw bytes; even a failed transfer must not lose d2kc.log.
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "sh -s -- /tmp/rr-$L" < "$(dirname "$0")/d2kfetch-export.sh" > "$R/probes.bundle" || transfer_rc=4
python3 -I "$(dirname "$0")/d2kfetch-import.py" "$R/probes.bundle" "$R" || transfer_rc=4
T0=$(head -1 "$R/t0.txt")
case "$T0" in
    [0-2][0-9]:[0-5][0-9]:[0-5][0-9])
$SSH "awk -v t0=$T0 '{ t = substr(\$0, 1, 8); ts = t ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\$/ } ts { if (t < p) n = 0; p = t } n || (ts && t >= t0) { b[++n] = \$0 } END { for (i = 1; i <= n; i++) print b[i] }' /opt/d2k/log/d2kc.log" > "$R/d2kc.log" || transfer_rc=4
        ;;
    *)
        # No trustworthy time boundary: retain evidence, but do not count it.
        $SSH "cat /opt/d2k/log/d2kc.log" > "$R/d2kc-unbounded.log"
        transfer_rc=4
        ;;
esac
if [ "$transfer_rc" = 0 ]; then
    $SSH "rm -rf /tmp/rr-$L /tmp/rr-$L.sh /tmp/rr-$L.targets /tmp/rr-$L.record"
else
    echo "неполный сбор; исходники оставлены на роутере" > "$R/collection-error.txt"
    echo "round-incomplete $L: исходники оставлены на роутере /tmp/rr-$L" >&2
fi
python3 -I "$(dirname "$0")/router-round-report.py" "$R" | tee "$R/report.txt"
[ "$transfer_rc" = 0 ] || exit "$transfer_rc"
echo "round-done $L"
