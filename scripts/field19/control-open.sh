#!/bin/sh
# Полевой инструмент: списки сайтов и пути без пробелов, разбиение по словам
# намеренное.
# shellcheck disable=SC2086
# control-open.sh <label> : контроль после замера — каждую страницу ОТКРЫТЬ заново.
# Новое окно Safari с 19 сайтами и новый запуск Chrome (профиль прогона, если есть),
# 50 с на загрузку, снимки обоих браузеров, curl против VPS, свои окна закрываются.
set -u
L=$1
F=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L/control; rm -rf $R; mkdir -p $R
P=$RUNS/chrome-profiles/$L; mkdir -p $P
URLS="https://rutracker.org/ https://fost.club/ https://nnmclub.to/ http://www.fast-torrent.ru/ https://lostfilm.tv/ https://kinozal.me/ https://bible-center.ru/ https://ru.numista.com/ https://rua.gr/ https://enimerosi.com/ https://romfea.gr/ https://katzauction.com/ https://spzh.eu/ru/ https://flibusta.is/ https://web.facebook.com/ https://adguard.com/ https://mailsuite.com/ https://cloudflare.com/ https://speed.cloudflare.com/"
for p in $(pgrep -f "Google Chrome --user-data-dir=$P"); do kill $p; done
while pgrep -f "user-data-dir=$P" >/dev/null; do sleep 1; done
date +%T > $R/t.txt
WID=$(osascript $F/open19.applescript); echo $WID > $R/wid
open -na "Google Chrome" --args --user-data-dir=$P --no-first-run --no-default-browser-check --hide-crash-restore-bubble --window-size=1300,900 $URLS
sleep 50
osascript $F/shoot_both.applescript $R $WID $P > $R/shoot.log 2>&1
python3 $F/sheet.py $R s 2 $R/safari.png
python3 $F/sheet.py $R c 1 $R/chrome.png
sh $F/curl19.sh $R/curl >/dev/null 2>&1
osascript -e "tell application \"Safari\" to close (first window whose id is $WID)" >/dev/null 2>&1
for p in $(pgrep -f "Google Chrome --user-data-dir=$P"); do kill $p; done
while pgrep -f "user-data-dir=$P" >/dev/null; do sleep 1; done
echo control-done $L
