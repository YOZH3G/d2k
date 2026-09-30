#!/bin/sh
# Удаление d2k с Keenetic.
#
# Убирает ТОЛЬКО своё: свои файлы, свою цепочку firewall, свои процессы.
# Чужого не трогает даже там, где похоже — правило соседа, снятое «на всякий
# случай», ломает соседа молча.
#
# Полное удаление, включая конфигурацию и каталог коробок, — поведение по
# умолчанию. Чтобы оставить изученное состояние, задайте D2K_KEEP_STATE=1.
set -eu

DIR=/opt/d2k
SBIN=/opt/sbin
INIT=/opt/etc/init.d/S99d2k
KEEP=${D2K_KEEP_STATE:-0}

say() { echo "d2k: $*"; }

# Remove only exact DNS pairs recorded by this installation. If NDM cannot
# confirm cleanup, stop before deleting the helper/manifest so the owner can
# retry rather than leaving unexplained static routes behind.
if [ -x "$DIR/d2k-instagram-dns.sh" ]; then
    say "снимаю свои Instagram DNS-записи"
    "$DIR/d2k-instagram-dns.sh" remove || {
        say "не удалось снять D2K Instagram DNS; удаление остановлено, повторите позже"
        exit 1
    }
fi

if [ -x "$INIT" ]; then
    say "останавливаю"
    "$INIT" stop || say "остановка вернула ошибку — продолжаю удаление"
fi

# Defense in depth when init has already been removed: stop only the owned
# Telegram PID and remove only the two D2K-owned redirect rule sets.
if [ -f "$DIR/run/d2ktg.pid" ]; then
    start-stop-daemon -K -q -p "$DIR/run/d2ktg.pid" 2>/dev/null || true
fi
if [ -f "$DIR/run/d2k-http.pid" ]; then
    start-stop-daemon -K -q -p "$DIR/run/d2k-http.pid" 2>/dev/null || true
fi
[ ! -x "$DIR/d2k-tg-firewall.sh" ] || "$DIR/d2k-tg-firewall.sh" stop >/dev/null 2>&1 || true
if command -v ipset >/dev/null 2>&1; then
    ipset destroy d2k_tg_dc 2>/dev/null || true
    ipset destroy d2k_tg_dc6 2>/dev/null || true
fi

# Цепочка снимается даже если init-скрипта уже нет: он мог быть удалён руками,
# а правила остаться.
# Старое имя D2K тоже снимается: установка прошлой версии могла оставить его.
for fw_tool in iptables ip6tables; do
while "$fw_tool" -t nat -D PREROUTING -j D2K_HTTP 2>/dev/null; do :; done
if "$fw_tool" -t nat -n -L D2K_HTTP >/dev/null 2>&1; then
    "$fw_tool" -t nat -F D2K_HTTP 2>/dev/null || true
    "$fw_tool" -t nat -X D2K_HTTP 2>/dev/null || true
fi
while "$fw_tool" -t mangle -D OUTPUT -j D2K_HTTP_MARK 2>/dev/null; do :; done
if "$fw_tool" -t mangle -n -L D2K_HTTP_MARK >/dev/null 2>&1; then
    "$fw_tool" -t mangle -F D2K_HTTP_MARK 2>/dev/null || true
    "$fw_tool" -t mangle -X D2K_HTTP_MARK 2>/dev/null || true
fi
for hook in POSTROUTING FORWARD OUTPUT INPUT; do
    for ch in D2K_OUT D2K_IN D2K; do
        while "$fw_tool" -t mangle -D "$hook" -j "$ch" 2>/dev/null; do :; done
    done
done
for ch in D2K_OUT D2K_IN D2K; do
    if "$fw_tool" -t mangle -n -L "$ch" >/dev/null 2>&1; then
        "$fw_tool" -t mangle -F "$ch" 2>/dev/null || true
        "$fw_tool" -t mangle -X "$ch" 2>/dev/null || true
    fi
done
done
say "правила сняты"

# Хук NDM снимается ПЕРВЫМ: оставленный, он будет звать сторожа, которого уже
# нет, на каждое изменение netfilter — мусор в журнале на ровном месте.
rm -f /opt/etc/ndm/netfilter.d/001-d2k.sh
rm -f "$INIT" "$SBIN/d2k" "$SBIN/d2kpanel" "$SBIN/d2kc" "$SBIN/d2kd" "$SBIN/d2ktg" "$SBIN/d2khttp"
# Remove only d2kc snapshots explicitly named as D2K pre-install/work backups.
# These were created during router development and are not user configuration.
rm -f "$SBIN"/d2kc.before-d2k-* "$SBIN"/d2kc.pre-goal-* "$SBIN"/d2kc.pre-sched-*
rm -f "$DIR/d2k-tg-firewall.sh" "$DIR/d2k-tg-watchdog.sh" "$DIR/d2k-instagram-dns.sh" \
    "$DIR/d2k-instagram-dns-scheduler.sh" \
    "$DIR/files/meta-ranges.txt" "$DIR/files/tg-roots.pem"
rm -rf "$DIR/run" "$DIR/log" "$DIR/panel"

if [ "$KEEP" = "1" ]; then
    say "сохраняю конфигурацию и каталог изученных коробок в $DIR"
    say "чтобы удалить всё: D2K_KEEP_STATE=0 sh $0"
    rm -f "$DIR/config.new"
else
    rm -rf "$DIR"
    say "удалено всё, включая каталог коробок"
fi

left=$({ iptables -t mangle -S 2>/dev/null || true; ip6tables -t mangle -S 2>/dev/null || true; } | grep -c -- "-j D2K" || true)
say "готово. Ссылок на цепочки d2k осталось: $left"
