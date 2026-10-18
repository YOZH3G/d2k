#!/bin/sh
# Полевой инструмент: списки сайтов и пути без пробелов, разбиение по словам
# намеренное.
# shellcheck disable=SC2086
# qwire.sh <label> [wait_s] : по какому протоколу Chrome на самом деле получил
# страницу. Для каждого сайта из SITES (по умолчанию 13 сайтов с HTTP/3 по VPS):
# адреса — через DNS роутера, tcpdump на ppp0 ловит UDP 443 и TCP 443 только к
# этим адресам, пока Chrome (профиль прогона) открывает сайт. Итог — байты от
# сервера по QUIC и по TCP. «Страница открылась» не доказывает QUIC: Chrome
# откатывается на TCP (15.10.2026).
set -u
L=$1; WAITP=${2:-15}
F=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
SITES=${SITES:-"1 2 3 5 6 9 10 11 12 13 15 16 18"}
HOSTS="rutracker.org fost.club nnmclub.to www.fast-torrent.ru lostfilm.tv kinozal.me bible-center.ru ru.numista.com rua.gr enimerosi.com romfea.gr katzauction.com spzh.eu flibusta.is web.facebook.com adguard.com mailsuite.com cloudflare.com speed.cloudflare.com"
OUTF=$RUNS/$L/qwire.txt; mkdir -p $RUNS/$L; : > $OUTF
i=0
for h in $HOSTS; do
    i=$((i+1))
    case " $SITES " in *" $i "*) ;; *) continue ;; esac
    ips=$(ssh -n -p 222 root@192.168.1.1 "nslookup $h 127.0.0.1 2>/dev/null | awk '/^Name:/{n=1;next} n && /^Address/ {print \$NF}' | grep -v ':'" | tr '\n' ' ')
    filt=""
    for a in $ips; do filt="${filt:+$filt or }host $a"; done
    if [ -z "$filt" ]; then echo "$i $h: адресов нет" >> $OUTF; continue; fi
    ssh -n -p 222 root@192.168.1.1 "rm -f /tmp/qw.pcap; (/opt/bin/tcpdump -i ppp0 -n -s 160 -w /tmp/qw.pcap '(udp port 443 or tcp port 443) and ($filt)' >/dev/null 2>&1 &); sleep 1"
    OUT=qwire SITES="$i" sh $F/control-one.sh $L $WAITP >/dev/null 2>&1
    cp $RUNS/$L/qwire/c$i.png $RUNS/$L/qwire-c$i.png 2>/dev/null
    r=$(ssh -n -p 222 root@192.168.1.1 "kill \$(pidof tcpdump) 2>/dev/null; sleep 1; /opt/bin/tcpdump -n -r /tmp/qw.pcap 2>/dev/null | awk '{src=\$3; sub(/\\.[0-9]+\$/, \"\", src); udp=(\$0 ~ / UDP, | udp /); len=\$NF+0; if (\$0 ~ /length [0-9]+/) { match(\$0, /length [0-9]+/); len=substr(\$0, RSTART+7, RLENGTH-7)+0 } out=(src ~ /^88\\.87\\.93\\.11/); if (udp && out) { uo++ } else if (udp) { ui++; ub+=len } else if (!out) { ti++; tb+=len } } END { printf \"QUIC наружу %d, внутрь %d датаграмм %d байт; TCP внутрь %d сегментов %d байт\", uo, ui, ub, ti, tb }'")
    echo "$i $h [$ips]: $r" >> $OUTF
done
cat $OUTF
echo qwire-done $L
