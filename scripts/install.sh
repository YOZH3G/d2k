#!/bin/sh
# Установка d2k на Keenetic.
#
# BusyBox ash. Каждый значимый отказ обрабатывается: установщик, который
# продолжает после неудачной загрузки, оставляет полусобранную систему, а
# человек об этом узнаёт от неработающего интернета.
#
# Что здесь НЕ делается и почему:
#   * ничего не берётся у z2k при неудаче загрузки — подмена артефактов
#     чужого продукта своими это не запасной путь, а сюрприз;
#   * фонового обновления нет: механизм не проверен, а непроверенное
#     автообновление хуже отсутствующего;
#   * подписи пока нет — это задача версии для общего пользования, и
#     обещать её здесь нельзя.
set -eu

REPO=${D2K_REPO:-necronicle/d2k}
REF=${D2K_REF:-main}
BASE=${D2K_BASE:-https://raw.githubusercontent.com/$REPO/$REF}

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
TMP=

say()  { echo "d2k: $*"; }
die()  { echo "d2k: $*" >&2; cleanup; exit 1; }
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; TMP=; }
trap cleanup EXIT INT TERM

# --- арка ----------------------------------------------------------------
#
# Отказ на неподдерживаемой арке ЯВНЫЙ. Поставить бинарник не той арки значит
# получить «не запускается» без объяснения.
case "$(uname -m)" in
    aarch64|arm64) ARCH=arm64 ;;
    *) die "C runtime пока собирается и проверяется только для ARM64, а здесь $(uname -m)" ;;
esac
say "архитектура: $(uname -m) -> $ARCH"

# --- что нужно от системы ------------------------------------------------
for t in curl ip iptables start-stop-daemon; do
    command -v "$t" >/dev/null 2>&1 || die "нет $t — поставьте пакет и повторите"
done
for t in ipset openssl; do
    command -v "$t" >/dev/null 2>&1 || die "нет $t — нужен для Telegram/Instagram; поставьте зависимости из README"
done
[ -e /proc/net/netfilter/nfnetlink_queue ] || \
    die "ядро без nfnetlink_queue — d2k работать не сможет"
grep -qw NFQUEUE /proc/net/ip_tables_targets 2>/dev/null || \
    die "в iptables нет цели NFQUEUE"
grep -qw connbytes /proc/net/ip_tables_matches 2>/dev/null || \
    die "в iptables нет совпадения connbytes"

# --- загрузка во временное место -----------------------------------------
#
# Сперва всё скачивается и проверяется, и только потом заменяется. Замена по
# ходу загрузки оставляет систему в состоянии, которого не предусматривал
# никто.
TMP=$(mktemp -d /tmp/d2k-install.XXXXXX) || die "не создать временный каталог"

fetch() {
    # $1 — путь в репозитории, $2 — куда положить.
    #
    # D2K_LOCAL берёт файлы из каталога вместо сети. Нужен для проверки
    # установки С ЧИСТОГО СОСТОЯНИЯ до того, как появятся опубликованные
    # сборки: обещать рабочую установку, ни разу её не пройдя, нельзя (§9).
    if [ -n "${D2K_LOCAL:-}" ]; then
        cp "$D2K_LOCAL/$1" "$2" || die "нет $D2K_LOCAL/$1"
    else
        curl -fsSL --max-time 120 -o "$2" "$BASE/$1" || die "не скачать $1"
    fi
    [ -s "$2" ] || die "$1 оказался пустым"
}

say "загрузка"
fetch "scripts/select-panel-ip.sh" "$TMP/select-panel-ip.sh"
fetch "builds/d2kpanel-linux-$ARCH" "$TMP/d2kpanel"
fetch "builds/d2kc-linux-$ARCH" "$TMP/d2kc"
fetch "builds/d2kd-linux-$ARCH" "$TMP/d2kd"
fetch "builds/d2ktg-linux-$ARCH" "$TMP/d2ktg"
fetch "files/S99d2k"            "$TMP/S99d2k"
fetch "files/config"            "$TMP/config"
fetch "files/d2k-fw-heal.sh"    "$TMP/d2k-fw-heal.sh"
fetch "files/001-d2k.sh"        "$TMP/001-d2k.sh"
fetch "files/d2k-tg-firewall.sh" "$TMP/d2k-tg-firewall.sh"
fetch "files/d2k-tg-watchdog.sh" "$TMP/d2k-tg-watchdog.sh"
fetch "files/d2k-instagram-dns.sh" "$TMP/d2k-instagram-dns.sh"
fetch "files/d2k-instagram-dns-scheduler.sh" "$TMP/d2k-instagram-dns-scheduler.sh"
fetch "files/meta-ranges.txt" "$TMP/meta-ranges.txt"
fetch "files/tg-roots.pem" "$TMP/tg-roots.pem"
fetch "files/fake/stun.bin" "$TMP/stun.bin"
fetch "files/fake/quic_initial_dbankcloud_ru.bin" "$TMP/quic_initial_dbankcloud_ru.bin"
mkdir -p "$TMP/panel"
fetch "internal/web/assets/index.html" "$TMP/panel/index.html"
fetch "internal/web/assets/panel.css"  "$TMP/panel/panel.css"
fetch "internal/web/assets/panel.js"   "$TMP/panel/panel.js"
fetch "internal/web/assets/logo-d2k.png" "$TMP/panel/logo-d2k.png"
fetch "internal/web/assets/mascot-d2k.png" "$TMP/panel/mascot-d2k.png"

chmod +x "$TMP/d2kpanel" "$TMP/d2kc" "$TMP/d2kd" "$TMP/d2ktg" \
         "$TMP/S99d2k" "$TMP/d2k-fw-heal.sh" "$TMP/001-d2k.sh" \
         "$TMP/d2k-tg-firewall.sh" "$TMP/d2k-tg-watchdog.sh" \
         "$TMP/d2k-instagram-dns.sh" "$TMP/d2k-instagram-dns-scheduler.sh"

# Проверка ДО замены: запускается ли то, что скачалось, и та ли это арка.
PANEL_VERSION=$("$TMP/d2kpanel" --version 2>/dev/null) || die "скачанный d2kpanel не запускается на этой системе"
case "$PANEL_VERSION" in
    *features=telegram-control*) ;;
    *) die "скачанный d2kpanel устарел: в нём нет управления Telegram-туннелем" ;;
esac
"$TMP/d2kd" --help  >/dev/null 2>&1 || die "скачанный d2kd не запускается на этой системе"
TG_VERSION=$("$TMP/d2ktg" --version 2>/dev/null) || die "скачанный d2ktg не запускается на этой системе"
case "$TG_VERSION" in
    *features=per-install-enrollment*) ;;
    *) die "скачанный d2ktg устарел: в нём нет автоматической регистрации установки" ;;
esac
case "$TG_VERSION" in
    *instagram-ip-probe*) ;;
    *) die "скачанный d2ktg устарел: нет проверки доступности Instagram IP" ;;
esac
# d2kc без обязательного --control печатает использование и выходит кодом 2 —
# это и есть признак «запускается и та арка». Ноль он здесь вернуть не может.
#
# Код снимается через `|| rc=$?`, а не отдельной строкой: при `set -e` (он
# стоит вверху) команда, вернувшая 2 вне условия, ЗАВЕРШАЕТ установщик молча
# — до всякой проверки. Ровно это и происходило: установка умирала на
# проверке арки, ничего не сказав человеку, и до подмены файлов не доходила
# никогда. Поймано scripts/lab-install.sh на первом же прогоне.
rc=0
"$TMP/d2kc" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || die "скачанный d2kc не запускается на этой системе (код $rc)"
say "проверено: $("$TMP/d2kpanel" --version | head -1)"

# --- остановка прежней версии --------------------------------------------
if [ -x "$INIT" ]; then
    say "останавливаю прежнюю версию"
    "$INIT" stop || say "прежняя версия остановилась с ошибкой — продолжаю"
fi

# --- атомарная замена ----------------------------------------------------
#
# Переименование в пределах одной ФС атомарно. Копирование поверх работающего
# бинарника — нет: на середине копирования файл уже не тот и ещё не этот.
mkdir -p "$DIR/state" "$DIR/run" "$DIR/log" "$DIR/panel" "$DIR/files/fake" "$SBIN" /opt/etc/init.d

install_atomic() {
    cp "$1" "$2.new" || die "не записать $2.new"
    chmod +x "$2.new"
    mv -f "$2.new" "$2" || die "не подменить $2"
}
install_data_atomic() {
    cp "$1" "$2.new" || die "не записать $2.new"
    chmod 0644 "$2.new"
    mv -f "$2.new" "$2" || die "не подменить $2"
}
install_atomic "$TMP/d2kpanel" "$SBIN/d2kpanel"
install_atomic "$TMP/d2kc"   "$SBIN/d2kc"
install_atomic "$TMP/d2kd"   "$SBIN/d2kd"
install_atomic "$TMP/d2ktg"  "$SBIN/d2ktg"
install_atomic "$TMP/S99d2k" "$INIT"
install_data_atomic "$TMP/panel/index.html" "$DIR/panel/index.html"
install_data_atomic "$TMP/panel/panel.css"  "$DIR/panel/panel.css"
install_data_atomic "$TMP/panel/panel.js"   "$DIR/panel/panel.js"
install_data_atomic "$TMP/panel/logo-d2k.png" "$DIR/panel/logo-d2k.png"
install_data_atomic "$TMP/panel/mascot-d2k.png" "$DIR/panel/mascot-d2k.png"
install_atomic "$TMP/d2k-fw-heal.sh" "$DIR/d2k-fw-heal.sh"
install_atomic "$TMP/d2k-tg-firewall.sh" "$DIR/d2k-tg-firewall.sh"
install_atomic "$TMP/d2k-tg-watchdog.sh" "$DIR/d2k-tg-watchdog.sh"
install_atomic "$TMP/d2k-instagram-dns.sh" "$DIR/d2k-instagram-dns.sh"
install_atomic "$TMP/d2k-instagram-dns-scheduler.sh" "$DIR/d2k-instagram-dns-scheduler.sh"
install_data_atomic "$TMP/meta-ranges.txt" "$DIR/files/meta-ranges.txt"
install_data_atomic "$TMP/tg-roots.pem" "$DIR/files/tg-roots.pem"
install_atomic "$TMP/stun.bin" "$DIR/files/fake/stun.bin"
install_atomic "$TMP/quic_initial_dbankcloud_ru.bin" "$DIR/files/fake/quic_initial_dbankcloud_ru.bin"
# Хук NDM — событийное восстановление правил. Каталог может отсутствовать на
# прошивке без netfilter.d: тогда остаётся периодический сторож, и это
# ухудшение страховки, а не отказ установки.
if [ -d /opt/etc/ndm/netfilter.d ]; then
    install_atomic "$TMP/001-d2k.sh" "/opt/etc/ndm/netfilter.d/001-d2k.sh"
else
    say "нет /opt/etc/ndm/netfilter.d — событийного восстановления правил не будет"
fi

# Конфигурация принадлежит человеку: существующую не трогаем.
if [ ! -f "$DIR/config" ]; then
    install_data_atomic "$TMP/config" "$DIR/config"
    say "создана конфигурация $DIR/config"
else
    say "конфигурация уже есть — не трогаю"
fi
# Fresh installs default to loopback in the template. Bind to the primary
# private router address instead, so every LAN device can open the panel
# directly while no public/WAN address is ever selected.
PANEL_LISTEN_CURRENT=$(sed -n 's/^PANEL_LISTEN=//p' "$DIR/config" | tail -n 1)
if [ "$PANEL_LISTEN_CURRENT" = "127.0.0.1:8090" ]; then
    PANEL_LAN_IP=$(ip -4 -o addr show scope global 2>/dev/null | sh "$TMP/select-panel-ip.sh") || \
        die "не удалось определить LAN-адрес роутера для панели"
    [ -n "$PANEL_LAN_IP" ] || die "не найден приватный LAN IPv4-адрес; панель не будет выставлена в интернет"
    sed "s|^PANEL_LISTEN=.*|PANEL_LISTEN=$PANEL_LAN_IP:8090|" "$DIR/config" > "$TMP/config.lan" || \
        die "не настроить LAN-адрес панели"
    install_data_atomic "$TMP/config.lan" "$DIR/config"
    say "панель доступна в LAN: http://$PANEL_LAN_IP:8090/"
fi
# В конфигурации хранится relay secret. Содержимое сохраняем, но ограничиваем
# чтение root даже при обновлении ранее установленного файла с более широкими
# правами.
chmod 0600 "$DIR/config" || die "не защитить права конфигурации"
# Upgrade the old unconfigured Telegram template without changing a user's
# enable/disable choice or custom relay. No fleet credential is installed.
TG_INSTALL_URL=$(sed -n 's/^TG_RELAY_URL=//p' "$DIR/config" | tail -n 1)
if [ -z "$TG_INSTALL_URL" ]; then
    printf '\nTG_RELAY_URL=wss://213.176.74.63.nip.io/ws\n' >> "$DIR/config"
    TG_INSTALL_URL=wss://213.176.74.63.nip.io/ws
fi
if [ "$TG_INSTALL_URL" = wss://213.176.74.63.nip.io/ws ] &&
   ! grep -q '^TG_ENROLL_PORT=' "$DIR/config"; then
    printf 'TG_ENROLL_PORT=9443\n' >> "$DIR/config"
fi
# Resolve and pin Instagram through the same authenticated VPS flow as z2k.
# A resolver/VPS outage must not turn a healthy D2K installation into a failure.
if "$DIR/d2k-instagram-dns.sh" refresh; then
    say "Instagram DNS проверен через VPS"
else
    say "Instagram DNS не обновлён: причина в $DIR/log/instagram-dns.log; прежние записи сохранены, повторы — с 04:00"
fi
# Убираем только legacy Go-панельный бинарник прежней установки; новый C
# runtime уже проверен выше и установлен отдельно как d2kpanel.
rm -f "$SBIN/d2k"

# --- запуск и проверка ---------------------------------------------------
say "запуск"
"$INIT" start || die "служба не запустилась"

sleep 2
if ! "$INIT" status | grep -q "датапат: работает"; then
    "$INIT" stop || true
    die "служба запустилась и умерла — смотрите $DIR/log/d2kd.log"
fi

"$INIT" status
if grep -q '^TG_ENABLED=1$' "$DIR/config"; then
    tg_wait=0
    while [ "$tg_wait" -lt 30 ] && [ "$(cat "$DIR/state/telegram.status" 2>/dev/null || true)" != connected ]; do
        sleep 1
        tg_wait=$((tg_wait + 1))
    done
    if [ "$(cat "$DIR/state/telegram.status" 2>/dev/null || true)" = connected ]; then
        say "Telegram: персональная регистрация и подключение к релею подтверждены"
    else
        say "Telegram ещё не подключён; автоматические повторы продолжаются, состояние видно в панели"
    fi
fi
PANEL_LISTEN=$(sed -n 's/^PANEL_LISTEN=//p' "$DIR/config" | tail -n 1)
if [ -n "$PANEL_LISTEN" ]; then
    say "панель слушает: http://$PANEL_LISTEN/"
else
    say "панель отключена (PANEL_LISTEN пуст в $DIR/config)"
fi
say "готово"
say "режим по умолчанию — активный обход (MODE=apply). Для наблюдения задайте MODE=observe."
