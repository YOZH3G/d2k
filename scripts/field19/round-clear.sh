#!/bin/sh
# Полевой инструмент: списки сайтов и пути без пробелов, разбиение по словам
# намеренное.
# shellcheck disable=SC2086
# round-clear.sh <label> : прогон поля, только Chrome (решение владельца 15.10.2026).
# clear-found (без установки), 19 сайтов в свежем профиле Chrome, curl против VPS
# через 1 мин и после контроля; через WAIT окна закрываются и каждый сайт
# открывается ЗАНОВО по одному (control-one.sh), снимки, журнал роутера.
#   EXPECT=<release-id> — остановиться, если на роутере другая сборка: замер
#                         сборки без последней правки ничего не стоит.
#   CLEAR=0   — каталог не чистить.
#   WAIT=<s>  — от открытия до контроля (по умолчанию 300).
#   DNS_GATE=1 — перед контролем остановиться, если DNS роутера падал с t0.
#   SITES=quic — только 13 сайтов с HTTP/3 (по VPS); SITES="1 5" — свои номера.
# На роутере всё время прогона пишется журнал живости d2kc: прогон с умершим
# контроллером ничего не мерил («Нет связи с датапатом», 15.10.2026).
set -u
L=$1
F=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L; rm -rf $R; mkdir -p $R
P=$RUNS/chrome-profiles/$L; rm -rf $P
URLS="https://rutracker.org/ https://fost.club/ https://nnmclub.to/ http://www.fast-torrent.ru/ https://lostfilm.tv/ https://kinozal.me/ https://bible-center.ru/ https://ru.numista.com/ https://rua.gr/ https://enimerosi.com/ https://romfea.gr/ https://katzauction.com/ https://spzh.eu/ru/ https://flibusta.is/ https://web.facebook.com/ https://adguard.com/ https://mailsuite.com/ https://cloudflare.com/ https://speed.cloudflare.com/"
# SITES="1 2 3" — только эти номера списка, и в обучении, и в контроле.
# QUIC_SITES — сайты с HTTP/3 по VPS (Alt-Svc h3 / HTTPS RR alpn h3, 15.10.2026).
QUIC_SITES="1 2 3 5 6 9 10 11 12 13 15 16 18"
[ "${SITES:-}" = quic ] && SITES=$QUIC_SITES
if [ -n "${SITES:-}" ]; then
    i=0; SEL=""
    for u in $URLS; do
        i=$((i+1))
        case " $SITES " in *" $i "*) SEL="$SEL $u" ;; esac
    done
    URLS=$SEL
fi
export SITES
RID=$(ssh -n -p 222 root@192.168.1.1 "cat /opt/d2k/release-id")
if [ -n "${EXPECT:-}" ] && [ "$RID" != "$EXPECT" ]; then
    echo "round-stopped $L: на роутере $RID, ожидалась $EXPECT"
    exit 4
fi
CLR="/opt/etc/init.d/S99d2k clear-found >/dev/null 2>&1;"; [ "${CLEAR:-1}" = 0 ] && CLR="echo catalog-kept;"
W=${WAIT:-300}
MON=$(( W + 450 ))
ssh -n -p 222 root@192.168.1.1 "$CLR date +%T | tee /tmp/dns-$L; cat /opt/d2k/release-id" > $R/t0.txt
T0=$(head -1 $R/t0.txt)
# ЖИВОСТЬ d2kc и МОНИТОР DNS (раз в 5 с через свой DNS 127.0.0.1; неудача хоть
# раз — прогон недействителен).
ssh -n -p 222 root@192.168.1.1 "rm -f /tmp/alive-$L /tmp/dnsmon-$L; ( trap '' HUP; end=\$((\$(date +%s) + $MON)); while [ \$(date +%s) -lt \$end ]; do echo \"\$(date +%T) \$(pidof d2kc)\" >> /tmp/alive-$L; for h in ya.ru rutracker.org flibusta.is rua.gr; do if nslookup \$h 127.0.0.1 2>/dev/null | awk '/^Name:/{n=1;next} n&&/^Address/{f=1} END{exit !f}'; then echo \"\$(date +%T) \$h ok\"; else echo \"\$(date +%T) \$h FAIL\"; fi; done >> /tmp/dnsmon-$L; sleep 5; done ) </dev/null >/dev/null 2>&1 &"
open -na "Google Chrome" --args --user-data-dir=$P --no-first-run --no-default-browser-check --window-size=1300,900 $URLS
osascript -e 'tell application "System Events" to set visible of application process "Terminal" to true' >/dev/null
sleep 60
sh $F/curl19.sh $R/curl1 >/dev/null 2>&1 &
sleep $((W - 60))
stop_chrome() {
    for p in $(pgrep -f "Google Chrome --user-data-dir=$P"); do kill $p; done
    while pgrep -f "user-data-dir=$P" >/dev/null; do sleep 1; done
}
if [ "${DNS_GATE:-0}" = 1 ]; then
    # Keenetic log lines: "E [Oct 15 09:43:59] ndm: Service: \"DoH ...\": unexpectedly".
    c=$(ssh -n -p 222 root@192.168.1.1 "ndmc -c 'show log' 2>/dev/null | grep -iE 'dns.*(unexpectedly|too many)' | awk -v t0=\$(cat /tmp/dns-$L) '{ t = substr(\$4, 1, 8) } t >= t0 { n++ } END { print n + 0 }'")
    m=$(ssh -n -p 222 root@192.168.1.1 "grep -c FAIL /tmp/dnsmon-$L 2>/dev/null; true" | head -1)
    d=$(( ${c:-1} + ${m:-1} ))
    echo "dns-failures-since-t0=$d (proxy-crash-lines=$c monitor-fails=$m)" > $R/dns-gate.txt
    if [ "${d:-1}" != 0 ]; then
        stop_chrome; wait
        echo "round-stopped $L: DNS proxy failed $d times since t0"
        exit 3
    fi
fi
stop_chrome
sh $F/control-one.sh $L 15 > $R/control-one.log 2>&1
sh $F/curl19.sh $R/curl2 >/dev/null 2>&1
wait
# Журнал по времени, а не по номеру строки: журнал ротируется посреди прогона.
# Журнал многодневный: строки прошлых суток позже t0 тоже «>= t0» (поле
# 16.10.2026, окно вышло отрицательным). Скачок времени назад сбрасывает набор.
ssh -n -p 222 root@192.168.1.1 "awk -v t0=$T0 '{ t = substr(\$0, 1, 8); ts = t ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\$/ } ts { if (t < p) n = 0; p = t } n || (ts && t >= t0) { b[++n] = \$0 } END { for (i = 1; i <= n; i++) print b[i] }' /opt/d2k/log/d2kc.log" > $R/d2kc.log
ssh -n -p 222 root@192.168.1.1 "cat /tmp/dnsmon-$L" > $R/dnsmon.txt 2>/dev/null
ssh -n -p 222 root@192.168.1.1 "cat /tmp/alive-$L" > $R/alive.txt 2>/dev/null
echo "DNS за прогон: $(grep -c ' ok$' $R/dnsmon.txt) ok, $(grep -c FAIL $R/dnsmon.txt) FAIL" >> $R/dns-gate.txt
# Перезапуск при clear-found — одна смена pid в начале; пустые строки и новые
# pid позже — контроллер падал.
awk '{print $2}' $R/alive.txt | uniq -c > $R/alive-summary.txt
echo "d2kc за прогон: $(awk 'NF<2{e++} END{print e+0}' $R/alive.txt) пропусков, pid: $(awk '{print $2}' $R/alive.txt | awk 'NF' | uniq | tr '\n' ' ')" >> $R/dns-gate.txt
echo round-done $L
