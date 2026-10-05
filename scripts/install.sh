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
#   * автообновление ставится только из ПОДПИСАННОГО выпуска: после плоской
#     установки скрипт берёт из канала stable загрузочный комплект своей
#     арки, проверяет подпись закреплённым ниже ключом и переводит установку
#     под d2k-update. Нет выпуска или подпись не сошлась — остаётся рабочая
#     плоская установка без автообновления, и это говорится словами.
set -eu

REPO=${D2K_REPO:-necronicle/d2k}
REF=${D2K_REF:-main}
BASE=${D2K_BASE:-https://raw.githubusercontent.com/$REPO/$REF}

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
# Explicit local bootstrap bundle is staged and verified by the operator/release
# tooling. No unsigned remote bootstrap is downloaded by this compatibility script.
if [ -n "${D2K_BOOTSTRAP_BUNDLE:-}" ]; then
    exec "$D2K_BOOTSTRAP_BUNDLE/d2k-update-boot" --root "$DIR" --bootstrap "$D2K_BOOTSTRAP_BUNDLE"
fi
# A managed root may only use the stable update entry; never replace individual
# files using this historical flat installer, even if current is damaged.
if [ -L "$DIR/current" ] || [ -d "$DIR/boot" ] || [ -d "$DIR/update-state" ]; then
    [ -x "$DIR/boot/d2k-service-adapter" ] || { echo 'd2k: managed recovery required' >&2; exit 1; }
    exec "$DIR/boot/d2k-service-adapter" service install
fi
TMP=

say()  { echo "d2k: $*"; }
die()  { echo "d2k: $*" >&2; cleanup; exit 1; }
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; TMP=; }
trap cleanup EXIT INT TERM

# --- арка ----------------------------------------------------------------
#
# Отказ на неподдерживаемой арке ЯВНЫЙ. Поставить бинарник не той арки значит
# получить «не запускается» без объяснения.

# --- что нужно от системы ------------------------------------------------
for t in curl ip iptables ip6tables start-stop-daemon; do
    command -v "$t" >/dev/null 2>&1 || die "нет $t — поставьте пакет и повторите"
done
for t in ipset openssl; do
    command -v "$t" >/dev/null 2>&1 || die "нет $t — нужен для Telegram/Instagram; поставьте зависимости из README"
done
# Модули netfilter прошивка часто держит файлами, но не загружает: в /proc
# видны только загруженные (Keenetic; Netis N6 04.10 — xt_connbytes ожил от
# modprobe). Установщик загружает их сам тем же способом, что S99d2k при
# старте, и только потом проверяет.
MODULES_DIR=${D2K_MODULES_DIR:-/lib/modules}
load_kmod() {
    modprobe "$1" 2>/dev/null && return 0
    kver=$(uname -r 2>/dev/null)
    ko=
    for d in "$MODULES_DIR/$kver" "$MODULES_DIR"; do
        [ -f "$d/$1.ko" ] && { ko="$d/$1.ko"; break; }
    done
    [ -n "$ko" ] || ko=$(find "$MODULES_DIR" -name "$1.ko" -type f 2>/dev/null | head -1)
    if [ -n "$ko" ]; then insmod "$ko" 2>/dev/null || true; fi
    # Всегда 0: под set -e неудача последней команды в «a || load_kmod»
    # оборвала бы установщик без объяснения; итог проверяется строкой ниже.
    return 0
}
NF_HINT="модуль не найден в прошивке; на Keenetic установите компонент «Модули ядра подсистемы Netfilter»"
[ -e /proc/net/netfilter/nfnetlink_queue ] || { load_kmod nfnetlink; load_kmod nfnetlink_queue; }
[ -e /proc/net/netfilter/nfnetlink_queue ] || \
    die "ядро без nfnetlink_queue — $NF_HINT"
grep -qw NFQUEUE /proc/net/ip_tables_targets 2>/dev/null || load_kmod xt_NFQUEUE
grep -qw NFQUEUE /proc/net/ip_tables_targets 2>/dev/null || \
    die "в iptables нет цели NFQUEUE — $NF_HINT"
grep -qw connbytes /proc/net/ip_tables_matches 2>/dev/null || load_kmod xt_connbytes
grep -qw connbytes /proc/net/ip_tables_matches 2>/dev/null || \
    die "в iptables нет совпадения connbytes — $NF_HINT"

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

fetch "scripts/architecture.sh" "$TMP/architecture.sh"
fetch "scripts/check-cpu.sh" "$TMP/check-cpu.sh"
SYS_ARCH=$(uname -m)
ENTWARE_ARCH=
if command -v opkg >/dev/null 2>&1; then
    ENTWARE_ARCH=$(opkg print-architecture 2>/dev/null | awk '
        $1 == "arch" && $2 != "all" && $2 != "noarch" {
            if ($3 + 0 >= priority) { priority = $3 + 0; arch = $2 }
        } END { print arch }')
fi
ARCH=$(sh "$TMP/architecture.sh" "$SYS_ARCH" "$ENTWARE_ARCH") || die "неподдерживаемая архитектура"
sh "$TMP/check-cpu.sh" "$ARCH" || die "CPU не соответствует требованиям сборки"
say "архитектура: $SYS_ARCH / ${ENTWARE_ARCH:-без Entware ABI} -> $ARCH"
say "загрузка"
fetch "scripts/select-panel-ip.sh" "$TMP/select-panel-ip.sh"
fetch "builds/d2kpanel-linux-$ARCH" "$TMP/d2kpanel"
fetch "builds/d2kc-linux-$ARCH" "$TMP/d2kc"
fetch "builds/d2kd-linux-$ARCH" "$TMP/d2kd"
fetch "builds/d2ktg-linux-$ARCH" "$TMP/d2ktg"
fetch "files/S99d2k"            "$TMP/S99d2k"
fetch "files/config"            "$TMP/config"
fetch "files/d2k-fw-heal.sh"    "$TMP/d2k-fw-heal.sh"
fetch "files/d2k-ppe-deoffload.sh" "$TMP/d2k-ppe-deoffload.sh"
fetch "files/d2k-log-maintenance.sh" "$TMP/d2k-log-maintenance.sh"
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
fetch "internal/web/assets/favicon.svg" "$TMP/panel/favicon.svg"
fetch "internal/web/assets/panel.css"  "$TMP/panel/panel.css"
fetch "internal/web/assets/panel.js"   "$TMP/panel/panel.js"
fetch "internal/web/assets/gsap.js"    "$TMP/panel/gsap.js"
for face in onest jbmono; do
    fetch "internal/web/assets/fonts/$face.woff2" "$TMP/panel/$face.woff2"
    fetch "internal/web/assets/fonts/OFL-$face.txt" "$TMP/panel/OFL-$face.txt"
done

chmod +x "$TMP/d2kpanel" "$TMP/d2kc" "$TMP/d2kd" "$TMP/d2ktg" \
         "$TMP/S99d2k" "$TMP/d2k-fw-heal.sh" "$TMP/d2k-ppe-deoffload.sh" "$TMP/d2k-log-maintenance.sh" "$TMP/001-d2k.sh" \
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
# The DNS helper pins 18 Instagram/fbcdn/WhatsApp names; an older d2ktg knows
# fewer and would silently reject the rest.
case "$TG_VERSION" in
    *meta-hosts-v3*) ;;
    *) die "скачанный d2ktg устарел: нет проверки сертификатов WhatsApp и fbcdn" ;;
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
# Прокси открытого HTTP (d2khttp) больше не нужен: вставку провайдера в
# HTTP узнаёт d2kd (задача 51). Прежняя версия уже остановлена выше вместе с
# его правилами; бинарник убираем.
rm -f "$SBIN/d2khttp"
install_atomic "$TMP/d2ktg"  "$SBIN/d2ktg"
install_atomic "$TMP/S99d2k" "$INIT"
install_data_atomic "$TMP/panel/index.html" "$DIR/panel/index.html"
install_data_atomic "$TMP/panel/favicon.svg" "$DIR/panel/favicon.svg"
install_data_atomic "$TMP/panel/panel.css"  "$DIR/panel/panel.css"
install_data_atomic "$TMP/panel/panel.js"   "$DIR/panel/panel.js"
install_data_atomic "$TMP/panel/gsap.js"    "$DIR/panel/gsap.js"
mkdir -p "$DIR/panel/fonts"
for face in onest jbmono; do
    install_data_atomic "$TMP/panel/$face.woff2" "$DIR/panel/fonts/$face.woff2"
    install_data_atomic "$TMP/panel/OFL-$face.txt" "$DIR/panel/fonts/OFL-$face.txt"
done
# Файлы прежней панели («Слайдоскоп») новой не нужны: убираем их при обновлении.
for old in slide-left.webp slide-center.webp slide-right.webp slide-holder.webp ground.webp \
           rack.webp family-rack.webp slide-left.webp.json slide-center.webp.json \
           slide-right.webp.json slide-holder.webp.json ground.webp.json rack.webp.json \
           family-rack.webp.json logo-d2k.png mascot-d2k.png mascot.svg \
           fonts/oswald.ttf fonts/OFL-oswald.txt; do
    rm -f "$DIR/panel/$old"
done
install_atomic "$TMP/d2k-fw-heal.sh" "$DIR/d2k-fw-heal.sh"
install_atomic "$TMP/d2k-ppe-deoffload.sh" "$DIR/d2k-ppe-deoffload.sh"
install_atomic "$TMP/d2k-log-maintenance.sh" "$DIR/d2k-log-maintenance.sh"
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
# Instagram/WhatsApp DNS pins come from d2k's own C resolver on the VPS.
# Checking 18 names can wait on silent edges, so the installer does not run it.
# A success younger than a day is kept: a release must not send the whole
# fleet to /resolve at once. An older mark (or one without its time, from an
# older version) is cleared, so the service's scheduler refreshes right after
# start, in the background. A resolver/VPS outage never fails the install.
DNS_MARK="$DIR/state/instagram-dns-last-success"
dns_mark_at=$(sed -n 2p "$DNS_MARK" 2>/dev/null || true)
dns_now=$(date +%s)
case "$dns_mark_at:$dns_now" in
    *[!0-9:]*|:*|*:) dns_mark_at= ;;
esac
if [ -n "$dns_mark_at" ] && [ "$dns_mark_at" -le "$dns_now" ] && [ $((dns_now - dns_mark_at)) -lt 86400 ]; then
    say "DNS Instagram/WhatsApp обновлялся меньше суток назад — следующее обновление по расписанию"
else
    rm -f "$DNS_MARK" /tmp/d2k-instagram-dns-last-attempt
    say "DNS Instagram/WhatsApp обновляется в фоне после запуска: результат в $DIR/log/instagram-dns.log; прежние записи сохраняются"
fi
say "далее — ежедневно в 01:00–04:59 (своя минута у каждой установки), при неудаче повтор с нарастающей паузой"
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
# --- автообновление ------------------------------------------------------
#
# Канал stable публикует .github/workflows/release.yml: release-тег
# d2k-channel-stable с подписанным stable.json и выпуски с загрузочным
# комплектом на каждую арку. Ключ закреплён здесь, а не берётся из сети:
# установщик приходит по HTTPS из того же репозитория, что и ключ.
UPDATE_FEED=${D2K_UPDATE_FEED:-https://github.com/$REPO/releases/download}
UPDATE_KEY='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqZkq/DsxeFJ1MCEEyFa7yzm80XiWf+cHPR1JsybbMPQ=
-----END PUBLIC KEY-----'
update_fetch() {
    curl -fsSL --proto '=https' --max-time 300 -o "$2" "$UPDATE_FEED/$1"
}
update_verified() {
    # $1 — документ, $2 — его подпись Ed25519 (64 байта).
    [ "$(wc -c < "$2" | tr -d ' ')" = 64 ] || return 1
    openssl pkeyutl -verify -pubin -inkey "$TMP/update-key.pem" -rawin \
        -in "$1" -sigfile "$2" >/dev/null 2>&1
}
enable_autoupdate() {
    printf '%s\n' "$UPDATE_KEY" > "$TMP/update-key.pem" || return 1
    if ! update_fetch d2k-channel-stable/stable.json "$TMP/stable.json" ||
       ! update_fetch d2k-channel-stable/stable.json.sig "$TMP/stable.json.sig"; then
        say "автообновление: подписанного выпуска ещё нет — работает плоская установка без автообновления"
        return 0
    fi
    update_verified "$TMP/stable.json" "$TMP/stable.json.sig" || {
        say "автообновление: подпись канала не сошлась — автообновление не включено"; return 1; }
    rid=$(sed -n 's/.*"release_id":"\([A-Za-z0-9][A-Za-z0-9._-]*\)".*/\1/p' "$TMP/stable.json")
    [ -n "$rid" ] || { say "автообновление: в канале нет выпуска"; return 1; }
    if ! { update_fetch "$rid/bootstrap-$ARCH.json" "$TMP/bootstrap.json" &&
           update_fetch "$rid/bootstrap-$ARCH.json.sig" "$TMP/bootstrap.json.sig"; }; then
        say "автообновление: в выпуске $rid нет комплекта для $ARCH"; return 1
    fi
    update_verified "$TMP/bootstrap.json" "$TMP/bootstrap.json.sig" || {
        say "автообновление: подпись комплекта $rid не сошлась"; return 1; }
    if ! { grep -q "\"abi\":\"$ARCH\"" "$TMP/bootstrap.json" &&
           grep -q "\"artifact\":\"d2k-bootstrap-$ARCH.tar\"" "$TMP/bootstrap.json"; }; then
        say "автообновление: комплект $rid не для $ARCH"; return 1
    fi
    update_fetch "$rid/d2k-bootstrap-$ARCH.tar" "$TMP/bootstrap.tar" || {
        say "автообновление: не скачать комплект $rid"; return 1; }
    # Подписан описатель, а в нём — хеш архива: архив принимается только
    # с ровно этим хешем.
    sum=$(openssl dgst -sha256 -r "$TMP/bootstrap.tar" | cut -d' ' -f1)
    case "$sum" in ''|*[!0-9a-f]*) return 1 ;; esac
    grep -q "\"sha256\":\"$sum\",\"size\":" "$TMP/bootstrap.json" || {
        say "автообновление: архив комплекта не совпал с подписанным описателем"; return 1; }
    mkdir "$TMP/bootstrap" && tar -xf "$TMP/bootstrap.tar" -C "$TMP/bootstrap" || return 1
    say "автообновление: перевожу установку под d2k-update (выпуск $rid)"
    "$TMP/bootstrap/d2k-update-boot" --root "$DIR" --bootstrap "$TMP/bootstrap" || {
        say "автообновление: перевод не выполнен — плоская установка продолжает работать"; return 1; }
    say "автообновление включено: новые выпуски ставятся ночью 03:00–05:00, вручную — кнопкой в панели"
}
if [ -n "${D2K_LOCAL:-}" ] || [ "${D2K_AUTOUPDATE:-1}" = 0 ]; then
    say "автообновление не включается (локальная установка или D2K_AUTOUPDATE=0)"
else
    enable_autoupdate || true
fi

say "готово"
say "режим по умолчанию — активный обход (MODE=apply). Для наблюдения задайте MODE=observe."
