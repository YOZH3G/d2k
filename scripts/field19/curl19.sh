#!/bin/sh
# Полевой инструмент: списки сайтов и пути без пробелов, разбиение по словам
# намеренное.
# shellcheck disable=SC2086
# curl19.sh <out> : 19 sites from mac (via router) and VPS in parallel; size vs VPS
OUT=$1
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36'
U="https://rutracker.org/forum/index.php https://fost.club/ https://nnmclub.to/ http://www.fast-torrent.ru/ https://www.lostfilm.tv/ https://kinozal.me/ https://bible-center.ru/ https://ru.numista.com/ https://rua.gr/ https://enimerosi.com/ https://romfea.gr/ https://katzauction.com/ru_index https://spzh.eu/ru/ https://flibusta.is/ https://web.facebook.com/ https://adguard.com/ru/welcome.html https://mailsuite.com/ru/ https://www.cloudflare.com/ https://speed.cloudflare.com/"
i=0; for u in $U; do i=$((i+1)); ( curl -s -o /dev/null -L --compressed -A "$UA" -m 30 -w "%{http_code} %{size_download} %{time_total} $u\n" "$u" > $OUT.mac.$i ) & done
ssh -n -i ~/.ssh/z2k_vps_ed25519 root@213.176.74.63 "for u in $U; do ( curl -s -o /dev/null -L --compressed -A '$UA' -m 30 -w '%{http_code} %{size_download} %{time_total} '\$u'\n' \"\$u\" ) & done; wait" > $OUT.vps
wait
cat $OUT.mac.* > $OUT.mac; rm -f $OUT.mac.*
for u in $U; do m=$(/usr/bin/grep " $u\$" $OUT.mac | head -1); v=$(/usr/bin/grep " $u\$" $OUT.vps | head -1); set -- $m; mc=$1 ms=$2 mt=$3; set -- $v; vc=$1 vs=$2; ok=НЕТ; if [ "${ms:-0}" -gt 0 ] && [ "${vs:-0}" -gt 0 ] && [ $((ms*100/vs)) -ge 90 ] && [ "$mc" = "$vc" ]; then ok=да; fi; printf '%-4s mac %s %7s Б %6ss | vps %s %7s Б | %s\n' "$ok" "$mc" "$ms" "$mt" "$vc" "$vs" "$(echo $u | sed -E 's#https?://##; s#/.*##')"; done > $OUT.txt
cat $OUT.txt
