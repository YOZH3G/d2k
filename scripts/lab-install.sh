#!/bin/sh
# lab-install.sh — УСТАНОВКА ЦЕЛИКОМ, НА ЧИСТОЙ СИСТЕМЕ, В КОНТЕЙНЕРЕ.
#
# Этап G требует шесть проверок: чистая установка, переход версии, неудачное
# обновление, остановка, возврат в прежний режим и удаление. Ни одна из них
# не проверяется чтением скрипта: установщик правит /opt, ставит init-скрипт
# и правила экрана, и «на взгляд правильно» здесь стоит ровно столько же,
# сколько стоило в files/S99d2k до scripts/check_firewall.sh — то есть нисколько.
#
# Роутер не трогается ничем. Всё происходит в контейнере, чей /opt и чей
# сетевой namespace создаются заново на каждый запуск, и который после
# прогона исчезает.
#
# ПОЧЕМУ ЭТО НЕ «ПОЧТИ РОУТЕР» И ЧТО ОСТАЁТСЯ НЕПРОВЕРЕННЫМ. Контейнер даёт
# ту же арку (aarch64), тот же netfilter и тот же start-stop-daemon, но не
# даёт Entware, NDM и флеш-память роутера. Значит здесь НЕ проверяются:
# поведение при сбросе правил силами NDM, хук /opt/etc/ndm/netfilter.d,
# переживание перезагрузки и износ флешки. Это названо прямо, а не скрыто
# зелёным прогоном.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$HERE/.." && pwd)

if ! docker info >/dev/null 2>&1; then
    echo "lab-install.sh: нужен запущенный Docker (docker info не отвечает)" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$ROOT" -cf - --exclude='.git' --exclude='*.o' --exclude='state' . | tar -C "$WORK" -xf -

cat > "$WORK/install-lab.sh" <<'DRIVER'
#!/bin/sh
set -e
cd /w

INIT=/opt/etc/init.d/S99d2k
DIR=/opt/d2k
REL=/tmp/rel

fail() { echo "ПРОВАЛ: $*" >&2; dump; exit 1; }
dump() {
    echo "--- статус ---";  [ -x "$INIT" ] && "$INIT" status 2>&1 || true
    echo "--- правила ---"; iptables -t mangle -S 2>&1 | grep -i d2k || echo "(нет)"
    echo "--- журналы ---"; tail -n 15 "$DIR"/log/*.log 2>/dev/null || true
}
sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
rules() { iptables -t mangle -S 2>/dev/null | sort; }

echo "== подготовка контейнера =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iptables >/dev/null 2>&1
command -v start-stop-daemon >/dev/null || fail "нет start-stop-daemon — установщик на такой системе не работает"

case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "C runtime устанавливается только под ARM64, а лаборатория запущена на $(uname -m)" ;;
esac
echo "арка: $(uname -m) -> $ARCH"

echo "== сборка того, что будет установлено =="
# Сборка НАТИВНАЯ: контейнер той же арки, что и роутер Марка (aarch64).
# Кросс-сборка проверяется отдельно, гейтом; здесь проверяется установка.
make -s -C core d2kc
make -s -C datapath d2kd

mkdir -p "$REL/builds" "$REL/files/fake" "$REL/internal/web/assets"
cp core/d2kc     "$REL/builds/d2kc-linux-$ARCH"
cp datapath/d2kd "$REL/builds/d2kd-linux-$ARCH"
make -s -C panel clean >/dev/null
make -s -C panel d2kpanel
cp panel/d2kpanel "$REL/builds/d2kpanel-linux-$ARCH"
cp internal/web/assets/index.html internal/web/assets/panel.css internal/web/assets/panel.js "$REL/internal/web/assets/"
cp files/S99d2k files/config files/d2k-fw-heal.sh files/001-d2k.sh "$REL/files/"
cp files/fake/stun.bin files/fake/quic_initial_dbankcloud_ru.bin "$REL/files/fake/"

# СНИМОК ЧИСТОЙ СИСТЕМЫ. По нему проверяются и остановка, и удаление: обе
# обязаны вернуть экран ровно в то состояние, в каком его застали.
CLEAN_RULES=$(rules)

echo "== 1. чистая установка =="
[ -e "$DIR" ] && fail "система не чистая: $DIR уже есть"
D2K_LOCAL="$REL" sh scripts/install.sh 2>&1 | tee /tmp/install1.log
[ "$(tail -1 /tmp/install1.log)" != "" ] || true
grep -q "готово" /tmp/install1.log || fail "установка с чистого состояния не прошла: $(tail -3 /tmp/install1.log)"

"$INIT" status | grep -q "датапат: работает" || fail "после установки датапат не работает"
"$INIT" status | grep -q "правила: стоят"    || fail "после установки правил нет"
"$INIT" status | grep -q "очередь .*привязана" || fail "очередь не привязана"
[ -x /opt/sbin/d2kd ] || fail "d2kd не установлен"
[ -x /opt/sbin/d2kc ] || fail "d2kc не установлен"
[ -x /opt/sbin/d2kpanel ] || fail "C-панель не установлена"
[ ! -x /opt/sbin/d2k ] || fail "legacy Go-панель осталась установленной"
[ -s "$DIR/panel/index.html" ] && [ -s "$DIR/panel/panel.css" ] && [ -s "$DIR/panel/panel.js" ] || fail "не установлены статические ресурсы панели"
[ -x "$INIT" ]        || fail "init-скрипт не установлен"
[ -f "$DIR/run/d2k-panel.pid" ] || fail "C-панель не получила pid-файл"
PANEL_PID=$(cat "$DIR/run/d2k-panel.pid")
[ -d "/proc/$PANEL_PID" ] || fail "C-панель умерла после старта"
PANEL_OK=0
i=0
while [ "$i" -lt 30 ]; do
    if curl -fsS http://127.0.0.1:8090/api/status -o /tmp/d2k-panel-status.json; then
        PANEL_OK=1
        break
    fi
    i=$((i + 1))
    sleep 0.1
done
[ "$PANEL_OK" = 1 ] || fail "C-панель не отдала /api/status"
grep -q '"snapshot"' /tmp/d2k-panel-status.json || fail "API не вернул status snapshot"
curl -fsS http://127.0.0.1:8090/ | grep -q 'id="app"' || fail "C-панель не отдала главную страницу"
echo "установлено и работает"

echo "== 2. переход версии =="
# Метка человека в конфигурации: обновление обязано её сохранить.
echo "# метка человека" >> "$DIR/config"
PID_BEFORE=$(cat "$DIR/run/d2kd.pid")

# ДРУГИЕ БАЙТЫ, ТО ЖЕ ПОВЕДЕНИЕ: пересобираем с другой оптимизацией. Это
# настоящая смена версии с точки зрения установщика (файл другой), и при
# этом не требует выдумывать «версию 2» там, где её ещё нет.
make -s -C panel clean >/dev/null
make -s -C panel d2kpanel CFLAGS="-O1 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L"
cp panel/d2kpanel "$REL/builds/d2kpanel-linux-$ARCH"
SHA_NEW=$(sha "$REL/builds/d2kpanel-linux-$ARCH")
[ "$SHA_NEW" != "$(sha /opt/sbin/d2kpanel)" ] || fail "новая сборка побайтно совпала со старой — переход версии не проверить"

D2K_LOCAL="$REL" sh scripts/install.sh 2>&1 | tee /tmp/install2.log
grep -q "готово" /tmp/install2.log || fail "переход версии не прошёл: $(tail -3 /tmp/install2.log)"
[ "$(sha /opt/sbin/d2kpanel)" = "$SHA_NEW" ] || fail "после обновления на месте осталась старая C-панель"
grep -q "^# метка человека" "$DIR/config" || fail "обновление затёрло конфигурацию человека"
PID_AFTER=$(cat "$DIR/run/d2kd.pid")
[ "$PID_AFTER" != "$PID_BEFORE" ] || fail "служба не перезапустилась — работает старый процесс"
"$INIT" status | grep -q "датапат: работает" || fail "после обновления датапат не работает"
echo "версия сменилась, конфигурация сохранена, служба перезапущена"

echo "== 3. неудачное обновление не трогает работающую =="
SHA_OK=$(sha /opt/sbin/d2kpanel)
PID_OK=$(cat "$DIR/run/d2kd.pid")
printf 'это не бинарник' > "$REL/builds/d2kpanel-linux-$ARCH"
if D2K_LOCAL="$REL" sh scripts/install.sh >/tmp/badinstall.log 2>&1; then
    fail "установщик принял испорченный бинарник"
fi
grep -q "не запускается" /tmp/badinstall.log || fail "отказ произошёл не там, где ждали: $(tail -1 /tmp/badinstall.log)"
[ "$(sha /opt/sbin/d2kpanel)" = "$SHA_OK" ] || fail "неудачное обновление подменило рабочую C-панель"
[ "$(cat "$DIR/run/d2kd.pid")" = "$PID_OK" ] || fail "неудачное обновление уронило работающую службу"
[ -d "/proc/$PID_OK" ] || fail "процесс службы умер после неудачного обновления"
"$INIT" status | grep -q "правила: стоят" || fail "неудачное обновление сняло правила"
echo "отказ до подмены: рабочая версия и правила не тронуты"

echo "== 4. остановка =="
"$INIT" stop >/dev/null
"$INIT" status | grep -q "датапат: не работает" || fail "после остановки датапат всё ещё работает"
[ -d "/proc/$PID_OK" ] && fail "процесс службы пережил остановку"

echo "== 5. возврат в прежний режим =="
# Экран обязан выглядеть ровно так, как до установки: не «похоже», а
# побайтно тот же список правил.
[ "$(rules)" = "$CLEAN_RULES" ] || {
    echo "--- было ---"; echo "$CLEAN_RULES"
    echo "--- стало ---"; rules
    fail "после остановки список правил не совпал с исходным"
}
# И обратно: служба поднимается снова тем же init-скриптом.
"$INIT" start >/dev/null
"$INIT" status | grep -q "датапат: работает" || fail "служба не поднялась после остановки"
echo "остановка и повторный запуск возвращают систему в оба состояния"

echo "== 6. удаление =="
sh scripts/uninstall.sh >/dev/null
[ -e /opt/sbin/d2kd ] && fail "после удаления остался d2kd"
[ -e /opt/sbin/d2kc ] && fail "после удаления остался d2kc"
[ -e /opt/sbin/d2kpanel ] && fail "после удаления осталась C-панель"
[ -e "$DIR/panel" ] && fail "после удаления остались ресурсы панели"
[ -e "$INIT" ]        && fail "после удаления остался init-скрипт"
[ "$(rules)" = "$CLEAN_RULES" ] || fail "после удаления список правил не совпал с исходным"
# Каталог изученных коробок по умолчанию сохраняется — это заявленное
# поведение, и проверяется оно так же, как всё остальное.
[ -d "$DIR/state" ] || fail "каталог коробок удалён, хотя обещано сохранить"
D2K_KEEP_STATE=0 sh scripts/uninstall.sh >/dev/null
[ -e "$DIR" ] && fail "явное удаление каталога оставило $DIR"
echo "удалено без следов; каталог коробок удаляется только по явному запросу"

echo
echo "УСТАНОВКА ПРОВЕРЕНА: шесть проверок этапа G пройдены на чистой системе"
DRIVER

docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
    -v "$WORK:/w" -w /w gcc:14 sh /w/install-lab.sh
