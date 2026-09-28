#!/bin/sh
set -eu

SCRIPT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/field-observe.sh

# Эти шаблоны проверяют исходник field-observe.sh, поэтому имена переменных
# в одинарных кавычках намеренно ищутся буквально, а не раскрываются shell.
# shellcheck disable=SC2016
grep -F -- 'iptables -t mangle -I OUTPUT -m mark --mark $CTL_MARK -m comment --comment $TOKEN -j CONNMARK --save-mark' "$SCRIPT" >/dev/null || {
    echo "FAIL: controller SO_MARK не сохраняется в conntrack" >&2
    exit 1
}

# shellcheck disable=SC2016
grep -F -- 'iptables -t mangle -I INPUT -m connmark --mark $CTL_MARK' "$SCRIPT" >/dev/null || {
    echo "FAIL: обратный трафик помеченного controller flow не маршрутизируется в очередь" >&2
    exit 1
}

# shellcheck disable=SC2016
grep -F -- 'iptables -t mangle -I POSTROUTING -p tcp --dport $PORTS -m mark --mark $CTL_MARK' "$SCRIPT" >/dev/null || {
    echo "FAIL: исходящий ClientHello локального зонда отсекается фильтром LAN-клиента" >&2
    exit 1
}

echo "PASS: controller replies идут по connmark, а не по адресу LAN-клиента"
