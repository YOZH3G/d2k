#!/bin/sh
# Полевой инструмент: списки сайтов и пути без пробелов, разбиение по словам
# намеренное.
# shellcheck disable=SC2086
# control-cdp.sh <label> [wait_s] : Network включён ДО навигации, кеш отключён.
# Ошибка документа/проверяемого ресурса даёт exit 1; повтор — отдельный pass.
# Снимок, DOM и сетевые события берутся через CDP (cdpobserve.mjs), а не
# screencapture области экрана. Окна пользователя не снимаются по построению,
# право «Универсальный доступ» не нужно. Chrome — настоящий, с окном, профиль
# прогона после обучения.
#   SITES="14 15" — только эти номера; OUT=<подкаталог> (по умолчанию cdp).
#   CONTROL_PASS=<n> — номер контрольного прохода, если история прогрева известна.
# Предыдущий OUT сохраняется рядом; повтор не стирает прежний неуспех.
set -u
L=$1; WAITP=${2:-20}
F=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RUNS=${D2K_FIELD_RUNS:-/Library/Zapret2/d2k-field-runs}
R=$RUNS/$L/${OUT:-cdp}
if [ -e "$R" ]; then
    PREVIOUS="$R.previous-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mv "$R" "$PREVIOUS" || exit 2
    echo "previous-control-preserved $PREVIOUS"
fi
mkdir -p "$R" || exit 2
P=$RUNS/chrome-profiles/$L; mkdir -p $P
PORT=${PORT:-9333}
# Count CDP invocations, not earlier training/native browser visits.
# The actual control pass is explicit or unknown; do not invent warm-up history.
PASS_FILE=$P/.d2k-control-pass
PREV=$(cat "$PASS_FILE" 2>/dev/null || echo 0)
case "$PREV" in ''|*[!0-9]*) echo 'invalid control pass counter' >&2; exit 2;; esac
PASS=$((PREV + 1)); printf '%s\n' "$PASS" > "$PASS_FILE"
printf 'control_pass=%s\ncdp_invocation=%s\nwait_s=%s\ncache_disabled=1\nobserver=network-before-navigation\n' "${CONTROL_PASS:-unknown}" "$PASS" "$WAITP" > "$R/control-context.txt"
stop() {
    for p in $(pgrep -f "Google Chrome --user-data-dir=$P"); do kill $p; done
    while pgrep -f "user-data-dir=$P" >/dev/null; do sleep 1; done
}
stop
ALL="https://rutracker.org/ https://fost.club/ https://nnmclub.to/ http://www.fast-torrent.ru/ https://lostfilm.tv/ https://kinozal.me/ https://bible-center.ru/ https://ru.numista.com/ https://rua.gr/ https://enimerosi.com/ https://romfea.gr/ https://katzauction.com/ https://spzh.eu/ru/ https://flibusta.is/ https://web.facebook.com/ https://adguard.com/ https://mailsuite.com/ https://cloudflare.com/ https://speed.cloudflare.com/"
i=0
for u in $ALL; do
    i=$((i+1))
    if [ -n "${SITES:-}" ]; then case " $SITES " in *" $i "*) ;; *) continue ;; esac; fi
    open -na "Google Chrome" --args --user-data-dir=$P --remote-debugging-port=$PORT --no-first-run --no-default-browser-check --hide-crash-restore-bubble --disable-features=Translate,TranslateUI --window-size=1300,900 about:blank
    printf '["%s"]\n' "$u" > "$R/url.json"
    node $F/cdpobserve.mjs $PORT "$R/network-$i" "$R/url.json" $WAITP > "$R/network-$i.log" 2>&1
    printf '%s %s ' "$i" "$u" >> $R/pages.txt
    python3 - "$R" "$i" <<'ENDPY' >> $R/pages.txt
import json,sys,shutil
from pathlib import Path
r=Path(sys.argv[1]); i=sys.argv[2]
try:
 d=json.loads((r/('network-'+i)/'1.json').read_text()); v=d.get('dom') or {}
 print(v.get('url','?'), '|', v.get('title','?'), '| текст',v.get('text',0),'симв.', '| observer',d.get('observerErrors'))
 p=r/('network-'+i)/'1.png'
 if p.exists(): shutil.copyfile(p,r/('c'+i+'.png'))
except Exception as e: print('cdp-error',str(e))
ENDPY
    stop
done
python3 $F/sheet.py $R c 1 $R/chrome.png 2>/dev/null
# Gate this single observation, without silent retries. It checks main
# documents plus known resource regressions, not every function of a site.
python3 "$F/resource-gate.py" "$R" ${SITES:-} > "$R/resource-gate.txt"
GATE=$?
cat "$R/resource-gate.txt"
echo "control-cdp-done $L pass=$PASS gate=$GATE"
exit "$GATE"
