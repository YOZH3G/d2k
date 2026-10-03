#!/bin/sh
# Unit-level check of files/S99d2k firewall bookkeeping with a stateful
# iptables/ip6tables double: IPv4-only start when ip6tables mangle is
# unusable (I4), and removal of leftover d2k-rst: RST-drop rules on stop.
# No Docker, no root, no netfilter: the real-iptables check stays
# scripts/check_firewall.sh (Docker). The double stores rules verbatim
# (minus "-m tcp" and quotes, as iptables -S normalises them) and matches
# -C/-D exactly, which is what these functions rely on.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
S99=$ROOT/files/S99d2k
TMP=$(mktemp -d)
SLEEPER=
cleanup() { [ -z "$SLEEPER" ] || kill "$SLEEPER" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

mkdir -p "$TMP/bin" "$TMP/fw" "$TMP/run" "$TMP/proc"
cat > "$TMP/bin/iptables" <<'EOF'
#!/bin/sh
# Stateful double: $FW_STATE/<tool>/<table>/<chain> holds one rule per line.
tool=$(basename "$0")
table=filter
op= chain=
spec=
while [ $# -gt 0 ]; do
    case "$1" in
        -w) shift ;;
        -n) shift ;;
        -t) table=$2; shift 2 ;;
        -N|-A|-I|-C|-D|-F|-X|-L) op=$1; chain=${2:-}; shift; [ $# -gt 0 ] && shift; break ;;
        -S) op=-S; chain=${2:-}; break ;;
        *) echo "stub: unexpected $1" >&2; exit 2 ;;
    esac
done
[ $# -eq 0 ] || spec=$(printf '%s ' "$@" | sed -e 's/ $//' -e 's/-m tcp //' -e 's/"//g')
if [ "$tool" = ip6tables ] && [ "$table" = mangle ] && [ "${STUB_V6_MANGLE_BROKEN:-0}" = 1 ]; then
    echo "ip6tables v1.4.21: can't initialize ip6tables table \`mangle': Table does not exist" >&2
    exit 3
fi
case " $spec " in *" ${STUB_FAIL_MATCH:-@none@} "*) [ "$tool" = "${STUB_FAIL_TOOL:-ip6tables}" ] && [ "$op" = -A ] && exit 1;; esac
dir=$FW_STATE/$tool/$table
mkdir -p "$dir"
for builtin in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do [ -e "$dir/$builtin" ] || : > "$dir/$builtin"; done
f=$dir/$chain
case "$op" in
    -N) [ ! -e "$f" ] || exit 1; : > "$f"; : > "$f.user" ;;
    -A) [ -e "$f" ] || exit 1; printf '%s\n' "$spec" >> "$f" ;;
    -I) [ -e "$f" ] || exit 1; { printf '%s\n' "$spec"; cat "$f"; } > "$f.new"; mv "$f.new" "$f" ;;
    -C) [ -e "$f" ] && grep -qxF -- "$spec" "$f" ;;
    -D) [ -e "$f" ] && grep -qxF -- "$spec" "$f" || exit 1
        awk -v s="$spec" '!d && $0==s {d=1; next} {print}' "$f" > "$f.new"; mv "$f.new" "$f" ;;
    -F) [ -e "$f" ] || exit 1; : > "$f" ;;
    -X) [ -e "$f.user" ] && [ ! -s "$f" ] || exit 1; rm -f "$f" "$f.user" ;;
    -L) [ -e "$f" ] ;;
    -S) if [ -n "$chain" ]; then
            [ -e "$f" ] || exit 1; sed "s/^/-A $chain /" "$f"
        else
            for c in "$dir"/*; do case "$c" in *.user|*.new) continue;; esac
                n=$(basename "$c"); [ -e "$c.user" ] && echo "-N $n"; sed "s/^/-A $n /" "$c"; done
        fi ;;
esac
EOF
chmod +x "$TMP/bin/iptables"
ln -s iptables "$TMP/bin/ip6tables"

# shellcheck disable=SC2016  # literal text searched for in S99d2k
CASE_LINE=$(grep -n '^case "$1" in' "$S99" | head -1 | cut -d: -f1)
[ -n "$CASE_LINE" ] || fail "S99d2k layout changed: no 'case \"\$1\" in'"
head -n "$((CASE_LINE - 1))" "$S99" > "$TMP/s99funcs.sh"

# Runs a snippet with the S99d2k functions, the doubles first on PATH and
# runtime paths inside the sandbox.
s99() {
    # shellcheck disable=SC2016  # expanded by the inner shell
    env FW_STATE="$TMP/fw" "$@" sh -c '
        . "$1/s99funcs.sh"
        PATH="$1/bin:$PATH"
        RUN=$1/run; FW_V4ONLY=$RUN/fw-ipv4-only; FW_LOCK=$1/fw.lock; PROC_DIR=$1/proc
        MODE=observe
        shift; eval "$1"' sh "$TMP" "$S99_SNIPPET"
}
rules() { FW_STATE="$TMP/fw" "$TMP/bin/$1" -t "$2" -S 2>/dev/null; }

# --- I4: ip6tables mangle unusable → IPv4-only, with a clear warning --------
S99_SNIPPET='fw_up && fw_installed' s99 || fail "baseline fw_up failed"
rules ip6tables mangle | grep -q -- '-N D2K_OUT' || fail "baseline did not set up IPv6"
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "IPv4-only marker without a reason"
S99_SNIPPET='fw_down' s99
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"

out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 STUB_V6_MANGLE_BROKEN=1 2>&1) \
    || { echo "$out" >&2; fail "fw_up refused to start without ip6tables mangle"; }
printf '%s\n' "$out" | grep -q 'только по IPv4' || fail "no clear IPv4-only warning: $out"
printf '%s\n' "$out" | grep -q INSTALLED || fail "fw_installed rejects the IPv4-only state"
[ -e "$TMP/run/fw-ipv4-only" ] || fail "IPv4-only state is not recorded"
rules iptables mangle | grep -q -- '-A POSTROUTING -j D2K_OUT' || fail "IPv4 rules missing in IPv4-only mode"
rules iptables mangle | grep -q -- '--queue-bypass' || fail "IPv4 queue rules missing in IPv4-only mode"
# The heal watchdog still notices an IPv4 rule removed by NDM.
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D FORWARD -j D2K_IN
if S99_SNIPPET='fw_installed' s99 STUB_V6_MANGLE_BROKEN=1; then fail "IPv4-only fw_installed missed a removed IPv4 jump"; fi
S99_SNIPPET='fw_down' s99 STUB_V6_MANGLE_BROKEN=1
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "fw_down kept the IPv4-only marker"
[ -z "$(rules iptables mangle | grep D2K || true)" ] || fail "fw_down left IPv4 rules in IPv4-only mode"
if S99_SNIPPET='fw_installed' s99 STUB_V6_MANGLE_BROKEN=1; then fail "fw_installed true after fw_down"; fi
ok "without ip6tables mangle the service runs IPv4-only and says so"

# A working ip6tables whose rule fails half-way is still a real error: both
# families roll back, as before.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
if S99_SNIPPET='fw_up' s99 STUB_FAIL_MATCH=connbytes STUB_FAIL_TOOL=ip6tables >/dev/null 2>&1; then
    fail "a failing IPv6 rule was taken for a missing IPv6 table"
fi
[ -z "$(rules iptables mangle | grep D2K || true)$(rules ip6tables mangle | grep D2K || true)" ] \
    || fail "partial IPv6 failure did not roll back both families"
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "partial IPv6 failure set IPv4-only"
ok "a partial IPv6 failure still rolls back both families"

# Прошивка без xt_addrtype (поле 03.10.2026, Keenetic mipsel 3.4_kn: «No
# chain/target/match by that name», служба не запускалась): исключения
# ставятся явными адресами, служба стартует и проверка правил её принимает.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 STUB_FAIL_MATCH=addrtype STUB_FAIL_TOOL=iptables 2>&1) \
    || { echo "$out" >&2; fail "fw_up refused to start without xt_addrtype"; }
printf '%s\n' "$out" | grep -q INSTALLED || { echo "$out" >&2; fail "rules without xt_addrtype not accepted as installed"; }
printf '%s\n' "$out" | grep -q "нет xt_addrtype" || fail "missing xt_addrtype not reported"
rules iptables mangle | grep -qx -- "-A D2K_OUT -d 255.255.255.255 -j RETURN" || fail "explicit broadcast RETURN missing"
! rules iptables mangle | grep -q addrtype || fail "addrtype rule present although unsupported"
ok "without xt_addrtype the service starts with explicit broadcast exclusions"

# --- Leftover d2k-rst: rules (filter OUTPUT, both families) ------------------
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
sleep 300 & SLEEPER=$!
dead=999990
while kill -0 "$dead" 2>/dev/null; do dead=$((dead + 1)); done
mkdir -p "$TMP/proc/$$" "$TMP/proc/$SLEEPER"
printf 'd2k-detect\n' > "$TMP/proc/$$/comm"     # a live d2k process
printf 'sshd\n' > "$TMP/proc/$SLEEPER/comm"      # a live foreign process
for tool in iptables ip6tables; do
    t() { FW_STATE="$TMP/fw" "$TMP/bin/$tool" -w "$@"; }
    t -A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40751 --tcp-flags RST RST -m comment --comment "d2k-rst:$$" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40752 --tcp-flags RST RST -m comment --comment "d2k-rst:$SLEEPER" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40753 --tcp-flags RST RST -m comment --comment "other:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 22 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40754 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j ACCEPT
done
# engine stop: only rules whose owner is gone (a live search keeps its own).
S99_SNIPPET='rst_rules_down dead' s99
for tool in iptables ip6tables; do
    r=$(rules "$tool" filter)
    ! printf '%s\n' "$r" | grep -q -- "--sport 40750 " || fail "$tool: rule of a dead owner survived engine stop"
    printf '%s\n' "$r" | grep -q -- "--sport 40751 " || fail "$tool: engine stop removed a live d2k process's rule"
done
# service stop / uninstall: every d2k-owned rule goes; foreign ones stay.
S99_SNIPPET='rst_rules_down all' s99
for tool in iptables ip6tables; do
    r=$(rules "$tool" filter)
    ! printf '%s\n' "$r" | grep -q -- "--sport 40751 " || fail "$tool: rule of a live d2k process survived service stop"
    printf '%s\n' "$r" | grep -q -- "--sport 40752 " || fail "$tool: rule owned by a non-d2k process was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 40753 " || fail "$tool: rule with a foreign comment was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 22 " || fail "$tool: rule outside the d2k port range was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 40754 " || fail "$tool: rule with another target was removed"
done
grep -q 'rst_rules_down dead' "$S99" || fail "engine_stop does not clean dead-owner RST rules"
grep -q 'rst_rules_down all' "$S99" || fail "stop does not clean d2k RST rules"
ok "stop removes leftover d2k-rst: rules in both families and nothing else"

echo "S99d2k firewall (stub): all checks passed"
