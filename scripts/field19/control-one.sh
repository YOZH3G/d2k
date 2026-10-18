#!/bin/sh
# Полевой инструмент: списки сайтов и пути без пробелов, разбиение по словам
# намеренное.
# shellcheck disable=SC2086
# control-one.sh <label> [wait_s] : контроль после замера — каждый сайт по одному,
# только Chrome (решение владельца 15.10.2026). Для каждого сайта — новый запуск
# Chrome с профилем прогона (профиль после обучения), ожидание (по умолчанию
# 15 с), снимок окна, Chrome закрывается.
set -u
L=$1; WAITP=${2:-15}
F=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L/${OUT:-one}; rm -rf $R; mkdir -p $R
P=$RUNS/chrome-profiles/$L; mkdir -p $P
for p in $(pgrep -f "Google Chrome --user-data-dir=$P"); do kill $p; done
while pgrep -f "user-data-dir=$P" >/dev/null; do sleep 1; done
i=0
ALL="https://rutracker.org/ https://fost.club/ https://nnmclub.to/ http://www.fast-torrent.ru/ https://lostfilm.tv/ https://kinozal.me/ https://bible-center.ru/ https://ru.numista.com/ https://rua.gr/ https://enimerosi.com/ https://romfea.gr/ https://katzauction.com/ https://spzh.eu/ru/ https://flibusta.is/ https://web.facebook.com/ https://adguard.com/ https://mailsuite.com/ https://cloudflare.com/ https://speed.cloudflare.com/"
# SITES="4 11 12" — только эти номера из списка (снимки сохраняют номер).
for u in $ALL; do
    i=$((i+1))
    if [ -n "${SITES:-}" ]; then case " $SITES " in *" $i "*) ;; *) continue ;; esac; fi
    open -na "Google Chrome" --args --user-data-dir=$P --no-first-run --no-default-browser-check --hide-crash-restore-bubble --disable-features=Translate,TranslateUI --window-size=1300,900 "$u"
    sleep $WAITP
    osascript - "$R" "$i" "$P" <<'AS' 2>&1 | head -2
on run argv
	set outdir to item 1 of argv
	set i to item 2 of argv
	set chromeprof to item 3 of argv
	tell application "System Events" to set visible of application process "Terminal" to false
	set pid to do shell script "pgrep -f 'Google Chrome --user-data-dir=" & chromeprof & "' | head -1"
	tell application "System Events"
		set p to first application process whose unix id is (pid as integer)
		set frontmost of p to true
		-- ОКНО ПРОГОНА ОБЯЗАНО БЫТЬ ВПЕРЕДИ. screencapture -R снимает ОБЛАСТЬ
		-- ЭКРАНА: если чужое окно перекрывает наше, в снимок попадает оно
		-- (поле 15.10.2026 — весь контроль снял личное окно владельца).
		delay 0.5
		set best to 0
		set bw to missing value
		repeat with cw in (windows of p)
			set sz to size of cw
			if ((item 1 of sz) * (item 2 of sz)) > best then
				set best to (item 1 of sz) * (item 2 of sz)
				set bw to cw
				set wpos to position of cw
				set wsz to sz
			end if
		end repeat
		if bw is missing value then error "у процесса прогона нет окна"
		-- ПОДНЯТЬ ИМЕННО НАШЕ ОКНО. macOS активирует ПРИЛОЖЕНИЕ, а не процесс:
		-- при запущенном Chrome владельца activate/frontmost выводит вперёд
		-- ЕГО окно, и `screencapture -R` снимал чужой экран (поле 15.10.2026,
		-- весь контроль ушёл в снимки личного окна). AXRaise поднимает
		-- конкретное окно поверх остальных, чужих не трогая.
		perform action "AXRaise" of bw
		delay 0.6
		do shell script "screencapture -x -R" & (item 1 of wpos) & "," & (item 2 of wpos) & "," & (item 1 of wsz) & "," & (item 2 of wsz) & " " & outdir & "/c" & i & ".png"
	end tell
	tell application "System Events" to set visible of application process "Terminal" to true
end run
AS
    for p in $(pgrep -f "Google Chrome --user-data-dir=$P"); do kill $p; done
    while pgrep -f "user-data-dir=$P" >/dev/null; do sleep 1; done
done
python3 $F/sheet.py $R c 1 $R/chrome.png
echo control-one-done $L
