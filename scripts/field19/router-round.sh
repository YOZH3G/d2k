#!/bin/sh
# router-round.sh <label> : прогон поля ЦЕЛИКОМ с роутера, без браузеров (решение
# владельца 17.10.2026). Чистый каталог, затем curl-impersonate по каждой цели: обучающие
# запросы в t0, t0+60, t0+120 с, контрольный — через WAIT с от t0. Итог по каждой
# цели и входа: код curl (0 — ответ полный), HTTP-код, размер, протокол; плюс
# журнал d2kc за прогон.
#   EXPECT=<release-id> — остановиться, если на роутере другая сборка.
#   WAIT=<s>            — от t0 до контроля (по умолчанию 240).
#   CLEAR=0             — каталог не чистить.
# Инструмент: /opt/d2k-tools/curl-impersonate (Chrome 150 с ECH, Safari 26, HTTP/3).
# Подресурсы страниц не грузятся — ключевые ресурсы перечислены отдельными целями.
set -u
L=$1
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L; rm -rf "$R"; mkdir -p "$R"
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=10 -p 222 root@192.168.1.1"
W=${WAIT:-240}
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
            j=\$(/opt/sbin/d2kfetch --name "\$1" --ip "\$ip" --path "\$3" --quic --deadline 15000 --json 2>/dev/null | tail -1)
            code=\$(echo "\$j" | sed -n 's/.*"http_status":\([0-9]*\).*/\1/p'); size=\$(echo "\$j" | sed -n 's/.*"quic_stream_bytes":\([0-9]*\).*/\1/p')
            case "\$j" in *'"response_complete":true'*) rc=0 ;; *) rc=1 ;; esac
            r="\"code\":\${code:-0},\"ver\":\"3\",\"size\":\${size:-0},\"t\":0,\"ip\":\"\$ip\""
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
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.targets" < "$R/targets.txt"
ssh -o BatchMode=yes -p 222 root@192.168.1.1 "cat > /tmp/rr-$L.sh" < "$R/round-router.sh"
$SSH "sh /tmp/rr-$L.sh"
$SSH "cat /tmp/rr-$L/t0" > "$R/t0.txt"; echo "$RID" >> "$R/t0.txt"
$SSH "cat /tmp/rr-$L/learn.jsonl" > "$R/learn.jsonl"
$SSH "cat /tmp/rr-$L/control.jsonl" > "$R/control.jsonl"
T0=$(head -1 "$R/t0.txt")
$SSH "awk -v t0=$T0 '{ t = substr(\$0, 1, 8); ts = t ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\$/ } ts { if (t < p) n = 0; p = t } n || (ts && t >= t0) { b[++n] = \$0 } END { for (i = 1; i <= n; i++) print b[i] }' /opt/d2k/log/d2kc.log" > "$R/d2kc.log"
$SSH "rm -rf /tmp/rr-$L /tmp/rr-$L.sh /tmp/rr-$L.targets"
python3 -I "$(dirname "$0")/router-round-report.py" "$R" | tee "$R/report.txt"
echo "round-done $L"
