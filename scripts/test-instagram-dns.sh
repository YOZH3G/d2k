#!/bin/sh
# Regression tests for the installer-owned Instagram/WhatsApp static DNS lifecycle.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SCRIPT=$ROOT/files/d2k-instagram-dns.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
export D2K_IP_CA_BUNDLE="$TMP/ca-bundle.pem"
printf 'test CA handled by the probe double\n' > "$D2K_IP_CA_BUNDLE"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

[ -x "$SCRIPT" ] || fail "Instagram resolver lifecycle script is missing or not executable"

# One host list: the router script, the d2ktg certificate check and the VPS
# allowlist must carry exactly the same names in the same order.
EXPECTED='instagram.com www.instagram.com graph.instagram.com api.instagram.com i.instagram.com instagram.c10r.instagram.com static.cdninstagram.com scontent.cdninstagram.com static.xx.fbcdn.net scontent.xx.fbcdn.net web.whatsapp.com www.whatsapp.com scontent.whatsapp.net graph.whatsapp.com v.whatsapp.com'
c_hosts() {
    sed -n '/META_HOSTS_BEGIN/,/META_HOSTS_END/p' "$1" | grep -o '"[a-z0-9.-]*"' | tr -d '"' | tr '\n' ' ' | sed 's/ $//'
}
script_hosts=$(sed -n "s/^HOSTS='\(.*\)'$/\1/p" "$SCRIPT")
[ "$script_hosts" = "$EXPECTED" ] || fail "router script host list differs: $script_hosts"
[ "$(c_hosts "$ROOT/telegram/src/main.c")" = "$EXPECTED" ] || fail "d2ktg check list differs: $(c_hosts "$ROOT/telegram/src/main.c")"
[ "$(c_hosts "$ROOT/relay-enroll/main.c")" = "$EXPECTED" ] || fail "VPS /resolve allowlist differs: $(c_hosts "$ROOT/relay-enroll/main.c")"
[ "$(echo "$EXPECTED" | wc -w | tr -d ' ')" = 15 ] || fail "host list must contain 15 names"
! grep -n 'instagram.com|www.instagram.com|' "$SCRIPT" >/dev/null || fail "managed_host carries a second hand-written host list"
ok "router script, d2ktg and VPS allowlist share one 15-name list"

mkdir -p "$TMP/bin" "$TMP/d2k/state" "$TMP/d2k/files" "$TMP/d2k/log"
printf 'D2K_RESOLVE_SECRET="test-secret"\nZ2K_RESOLVE_SECRET="old-secret"\n' > "$TMP/d2k/config"
printf '157.240.0.0/16\n57.144.0.0/14\n' > "$TMP/d2k/files/meta-ranges.txt"
cat > "$TMP/ndmc-state" <<'EOF'
ip host www.instagram.com 157.240.9.175
ip host instagram.com 203.0.113.10
ip host unrelated.example 192.0.2.7
EOF

cat > "$TMP/bin/ndmc" <<'EOF'
#!/bin/sh
case "$*" in
    *"show running-config"*) [ "${NDMC_FAIL_SHOW:-0}" = 1 ] && exit 7; cat "$NDMC_STATE" ;;
    *"system configuration save"*) [ "${NDMC_FAIL_SAVE:-0}" = 1 ] && exit 8; : ;;
    "-c ip host "*)
        if [ "${NDMC_TERM_DURING_ADD:-0}" = 1 ]; then
            printf '%s\n' "$*" >> "$NDMC_CALLS"
            kill -TERM "$PPID"; sleep 1
            printf 'ip host %s %s\n' "$(echo "$2" | awk '{print $3}')" "$(echo "$2" | awk '{print $4}')" >> "$NDMC_STATE"
            exit 0
        fi
        [ "${NDMC_FAIL_ADD:-0}" = 1 ] && exit 6
        printf '%s\n' "$*" >> "$NDMC_CALLS"
        printf 'ip host %s %s\n' "$(echo "$2" | awk '{print $3}')" "$(echo "$2" | awk '{print $4}')" >> "$NDMC_STATE"
        # Simulates uninstall stopping a background refresh right after NDM
        # accepted a record.
        [ "${NDMC_KILL_AFTER_ADD:-0}" = 1 ] && kill -9 "$PPID"
        :
        ;;
    "-c no ip host "*)
        printf '%s\n' "$*" >> "$NDMC_CALLS"
        host=$(echo "$2" | awk '{print $4}')
        ip=$(echo "$2" | awk '{print $5}')
        awk -v h="$host" -v ip="$ip" '!( $1=="ip" && $2=="host" && $3==h && $4==ip )' "$NDMC_STATE" > "$NDMC_STATE.new"
        mv "$NDMC_STATE.new" "$NDMC_STATE"
        ;;
    *) printf 'unexpected ndmc call: %s\n' "$*" >&2; exit 2 ;;
esac
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$CURL_CALLS"
case "$*" in
    */resolve*)
        [ "${RESOLVE_FAIL:-0}" = 1 ] && exit 22
        calls=$(grep -c '/resolve' "$CURL_CALLS" 2>/dev/null || echo 0)
        [ "$calls" -le "${RESOLVE_FAIL_FIRST:-0}" ] && exit 28
        printf '{"results":{"instagram.com":["%s","8.8.8.8","%s","157.240.9.177","157.240.9.178"],"www.instagram.com":["157.240.9.175"],"not-instagram.example":["157.240.9.179"],"i.instagram.com":["157.240.9.63"],"static.xx.fbcdn.net":["%s"],"scontent.xx.fbcdn.net":["%s"],"web.whatsapp.com":["%s","57.144.245.33"],"v.whatsapp.com":[],"evil.whatsapp.com":["57.144.245.40"]}}' \
            "${VPS_IP1:-157.240.9.174}" "${VPS_IP2:-157.240.9.176}" "${FB_IP:-157.240.205.11}" "${FB_IP:-157.240.205.11}" "${WA_IP:-57.144.245.32}"
        ;;
    *)
        probes=$(grep -vc '/resolve' "$CURL_CALLS" 2>/dev/null || echo 0)
        if [ "$probes" -le "${PROBE_FAIL_FIRST:-0}" ]; then printf '000'; exit 28; fi
        printf '200'
        ;;
esac
EOF
cat > "$TMP/bin/openssl" <<'EOF'
#!/bin/sh
printf 'openssl %s\n' "$*" >> "$OPENSSL_KEY"
exit 1
EOF
cat > "$TMP/bin/d2ktg" <<'EOF'
#!/bin/sh
[ "$1" = --check-instagram-ip ] && [ "$#" = 4 ] || exit 2
printf '%s\n' "$*" >> "$CURL_CALLS"
[ "${PROBE_FAIL_ALL:-0}" = 1 ] && exit 1
probes=$(grep -c -- '--check-instagram-ip' "$CURL_CALLS" || true)
[ "$probes" -gt "${PROBE_FAIL_FIRST:-0}" ]
EOF
chmod +x "$TMP/bin/ndmc" "$TMP/bin/curl" "$TMP/bin/openssl" "$TMP/bin/d2ktg"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" \
    CURL_CALLS="$TMP/curl-calls" OPENSSL_KEY="$TMP/openssl-key" \
    D2K_IP_PROBE_RETRY_DELAY=0 PROBE_FAIL_FIRST=1 \
    D2K_INSTAGRAM_LOG="$TMP/refresh.log" sh "$SCRIPT" refresh || fail "refresh failed"

grep -q '^ip host instagram.com 157.240.9.174$' "$TMP/ndmc-state" || { cat "$TMP/refresh.log" >&2; cat "$TMP/ndmc-calls" >&2; fail "VPS Instagram address was not added"; }
grep -q '^ip host instagram.com 157.240.9.176$' "$TMP/ndmc-state" || fail "second live Instagram edge was not added"
! grep -Eq '^ip host instagram.com 157.240.9.177$|^ip host instagram.com 157.240.9.178$' "$TMP/ndmc-state" || fail "more than two live edges were pinned for one host"
grep -q '^ip host instagram.com 203.0.113.10$' "$TMP/ndmc-state" || fail "pre-existing user mapping was changed"
grep -q '^ip host www.instagram.com 157.240.9.175$' "$TMP/ndmc-state" || fail "identical pre-existing mapping was lost"
! grep -q '8.8.8.8\|not-instagram.example' "$TMP/ndmc-calls" || fail "untrusted or non-Instagram answer reached ndmc"
grep -q '^instagram.com 157.240.9.174$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "ownership manifest omitted added address"
grep -q '^instagram.com 157.240.9.176$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "ownership manifest omitted second added address"
[ "$(grep -c '^instagram.com ' "$TMP/d2k/state/instagram-ip-hosts.tsv")" = 2 ] || fail "manifest does not track both installed edges"
! grep -q '^www.instagram.com ' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "pre-existing mapping was incorrectly claimed"
! grep -qi 'X-Z2K-Auth\|hmac\|test-secret\|old-secret' "$TMP/curl-calls" || fail "d2k resolver request still carries z2k HMAC authentication"
[ ! -e "$TMP/openssl-key" ] || fail "refresh still computes an HMAC with openssl"
body=$(printf '{"hosts":["%s"]}' "$(echo "$EXPECTED" | sed 's/ /","/g')")
grep -qF -- "--data $body" "$TMP/curl-calls" || fail "VPS request did not contain all 15 names in order"
grep -q '^ip host i.instagram.com 157.240.9.63$' "$TMP/ndmc-state" || fail "i.instagram.com was not pinned"
grep -q '^ip host static.xx.fbcdn.net 157.240.205.11$' "$TMP/ndmc-state" || fail "static.xx.fbcdn.net was not pinned"
grep -q '^ip host scontent.xx.fbcdn.net 157.240.205.11$' "$TMP/ndmc-state" || fail "scontent.xx.fbcdn.net was not pinned"
grep -q '^ip host web.whatsapp.com 57.144.245.32$' "$TMP/ndmc-state" || fail "WhatsApp Web address was not pinned"
grep -q '^ip host web.whatsapp.com 57.144.245.33$' "$TMP/ndmc-state" || fail "second WhatsApp Web edge was not pinned"
grep -q '^web.whatsapp.com 57.144.245.32$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest does not own the WhatsApp pin"
grep -q '^static.xx.fbcdn.net 157.240.205.11$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest does not own the fbcdn pin"
! grep -q 'evil.whatsapp.com\|57.144.245.40' "$TMP/ndmc-calls" "$TMP/curl-calls" || fail "a name outside the list reached ndmc or the certificate check"
grep -q -- '--check-instagram-ip web.whatsapp.com 57.144.245.32' "$TMP/curl-calls" || fail "WhatsApp address skipped the certificate check"
grep -q -- '--check-instagram-ip instagram.com 157.240.9.174' "$TMP/curl-calls" || fail "DNS health still depends on blocked application HTTPS instead of certificate-verified edge health"
grep -q 'повтор TLS-пробы 1/2' "$TMP/refresh.log" || fail "transient IP probe failure was not retried"
ok "refresh pins VPS-verified Instagram, fbcdn and WhatsApp IPs and records only D2K-owned pairs"

# Without an override the router asks d2k's own C resolver on the enrollment
# port, pinning the nip.io name to its literal address on that same port.
DEF="$TMP/default"
mkdir -p "$DEF/d2k/state" "$DEF/d2k/files" "$DEF/d2k/log"
: > "$DEF/d2k/config"; cp "$TMP/d2k/files/meta-ranges.txt" "$DEF/d2k/files/"
: > "$DEF/ndmc-state"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$DEF/d2k" D2K_CONFIG="$DEF/d2k/config" \
    D2K_META_RANGES="$DEF/d2k/files/meta-ranges.txt" \
    NDMC_STATE="$DEF/ndmc-state" NDMC_CALLS="$DEF/ndmc-calls" \
    CURL_CALLS="$DEF/curl-calls" OPENSSL_KEY="$DEF/openssl-key" \
    D2K_INSTAGRAM_LOG="$DEF/refresh.log" sh "$SCRIPT" refresh || { cat "$DEF/refresh.log" >&2; fail "refresh against the default resolver failed"; }
grep -q -- '--resolve 213.176.74.63.nip.io:9443:213.176.74.63 -X POST https://213.176.74.63.nip.io:9443/resolve' "$DEF/curl-calls" \
    || { cat "$DEF/curl-calls" >&2; fail "default resolver is not d2k's own https://213.176.74.63.nip.io:9443/resolve"; }
! grep -q 'nip.io/resolve\|:443:' "$DEF/curl-calls" || fail "refresh still calls the z2k relay /resolve on 443"
ok "default resolver is d2k's own C /resolve on port 9443 without authentication"

: > "$TMP/curl-calls"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" D2K_RELAY_URL=https://resolve.example/resolve \
    VPS_IP1=157.240.9.180 VPS_IP2=157.240.9.181 \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    OPENSSL_KEY="$TMP/openssl-key" D2K_INSTAGRAM_LOG="$TMP/replace.log" sh "$SCRIPT" refresh \
    || fail "refresh could not replace old D2K-owned pairs"
grep -q '^ip host instagram.com 157.240.9.180$' "$TMP/ndmc-state" || fail "new edge was not installed"
grep -q '^ip host instagram.com 157.240.9.181$' "$TMP/ndmc-state" || fail "second new edge was not installed"
! grep -q '^ip host instagram.com 157.240.9.174$\|^ip host instagram.com 157.240.9.176$' "$TMP/ndmc-state" || fail "stale D2K-owned edges survived replacement"
grep -q '^ip host instagram.com 203.0.113.10$' "$TMP/ndmc-state" || fail "replacement removed a user-owned record"
grep -q '^instagram.com 157.240.9.180$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest lacks the refreshed edge"
! grep -q '^instagram.com 157.240.9.174$\|^instagram.com 157.240.9.176$' "$TMP/d2k/state/instagram-ip-hosts.tsv" || fail "manifest retained stale edges"
ok "successful refresh replaces stale D2K-owned pairs without touching user DNS"

cp "$TMP/ndmc-state" "$TMP/before-add-failure"
if env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" NDMC_FAIL_ADD=1 \
    D2K_RELAY_URL=https://resolve.example/resolve VPS_IP1=157.240.9.182 VPS_IP2=157.240.9.183 \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    OPENSSL_KEY="$TMP/openssl-key" D2K_INSTAGRAM_LOG="$TMP/add-failure.log" sh "$SCRIPT" refresh; then
    fail "refresh reported success although NDM rejected new pins"
fi
cmp -s "$TMP/before-add-failure" "$TMP/ndmc-state" || fail "old working pins removed despite failure to install replacements"
ok "failed NDM additions preserve previous pins and report failure"

if env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" PROBE_FAIL_ALL=1 \
    D2K_IP_PROBE_ATTEMPTS=1 D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    OPENSSL_KEY="$TMP/openssl-key" D2K_INSTAGRAM_LOG="$TMP/tls-failure.log" sh "$SCRIPT" refresh; then
    fail "refresh accepted failed certificate/reachability probes"
fi
cmp -s "$TMP/before-add-failure" "$TMP/ndmc-state" || fail "failed TLS controls changed DNS"
ok "failed edge verification never replaces working DNS"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/remove.log" sh "$SCRIPT" remove || fail "remove failed"

! grep -q '^ip host instagram.com 157.240.9.180$\|^ip host instagram.com 157.240.9.181$' "$TMP/ndmc-state" || fail "D2K-owned mappings survived removal"
! grep -q 'whatsapp\|fbcdn\|i.instagram.com' "$TMP/ndmc-state" || fail "D2K-owned WhatsApp/fbcdn/i.instagram pins survived removal"
grep -q '^ip host instagram.com 203.0.113.10$' "$TMP/ndmc-state" || fail "removal deleted a user-owned mapping"
grep -q '^ip host www.instagram.com 157.240.9.175$' "$TMP/ndmc-state" || fail "removal deleted a pre-existing identical mapping"
[ ! -e "$TMP/d2k/state/instagram-ip-hosts.tsv" ] || fail "ownership manifest survived removal"
ok "remove deletes exact D2K-owned pairs and preserves user mappings"

cp "$TMP/ndmc-state" "$TMP/before-failed-refresh"
: > "$TMP/curl-calls"
if env D2K_STUB_PATH="$TMP/bin" RESOLVE_FAIL=1 D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" \
    D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" OPENSSL_KEY="$TMP/openssl-key" \
    D2K_RESOLVE_RETRY_DELAY=0 \
    D2K_INSTAGRAM_LOG="$TMP/failure.log" sh "$SCRIPT" refresh; then
    fail "refresh treated unavailable VPS as successful"
fi
cmp -s "$TMP/before-failed-refresh" "$TMP/ndmc-state" || fail "VPS failure changed static DNS records"
[ "$(grep -c '/resolve' "$TMP/curl-calls")" = 3 ] || fail "resolver failure did not use the configured retry budget"
grep -q 'текущие DNS-записи не изменены' "$TMP/failure.log" || fail "VPS failure was not clearly logged"
ok "resolver failure retries three times and leaves all DNS records untouched"

: > "$TMP/curl-calls"
env D2K_STUB_PATH="$TMP/bin" RESOLVE_FAIL_FIRST=2 D2K_RESOLVE_RETRY_DELAY=0 \
    D2K_DIR="$TMP/d2k" D2K_CONFIG="$TMP/d2k/config" D2K_META_RANGES="$TMP/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_STATE="$TMP/ndmc-state" \
    NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" OPENSSL_KEY="$TMP/openssl-key" \
    D2K_INSTAGRAM_LOG="$TMP/retry.log" sh "$SCRIPT" refresh || fail "refresh did not recover after transient VPS failures"
[ "$(grep -c '/resolve' "$TMP/curl-calls")" = 3 ] || fail "refresh did not recover on its third VPS attempt"
grep -q '^ip host instagram.com 157.240.9.174$' "$TMP/ndmc-state" || fail "recovered VPS answer was not applied"
! grep -Eqi 'fallback|резервн' "$TMP/retry.log" || fail "refresh introduced a hard-coded fallback"
ok "resolver retry recovers and applies only live VPS results"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" NDMC_STATE="$TMP/ndmc-state" \
    NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/retry-remove.log" sh "$SCRIPT" remove || fail "retry-result cleanup failed"

printf 'ip host instagram.com 157.240.9.174\n' >> "$TMP/ndmc-state"
printf 'instagram.com 157.240.9.174\n' > "$TMP/d2k/state/instagram-ip-hosts.tsv"
if env D2K_STUB_PATH="$TMP/bin" NDMC_FAIL_SAVE=1 D2K_DIR="$TMP/d2k" \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/remove-failure.log" sh "$SCRIPT" remove; then
    fail "remove hid an NDM save failure"
fi
[ -s "$TMP/d2k/state/instagram-ip-hosts.tsv" ] || fail "failed cleanup discarded ownership manifest"
ok "failed NDM save keeps the ownership manifest for retry"

env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$TMP/d2k" \
    NDMC_STATE="$TMP/ndmc-state" NDMC_CALLS="$TMP/ndmc-calls" CURL_CALLS="$TMP/curl-calls" \
    D2K_INSTAGRAM_LOG="$TMP/remove-retry.log" sh "$SCRIPT" remove || fail "cleanup retry failed"
[ ! -e "$TMP/d2k/state/instagram-ip-hosts.tsv" ] || fail "successful cleanup retry kept the manifest"
ok "cleanup retry persists removal and then clears the manifest"

# A refresh killed right after NDM accepted a pin (service stop, uninstall)
# must already own it, so remove can take it back.
KILL="$TMP/killed"
mkdir -p "$KILL/d2k/state" "$KILL/d2k/files" "$KILL/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$KILL/d2k/files/"
printf 'ip host unrelated.example 192.0.2.7\n' > "$KILL/ndmc-state"
if (env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$KILL/d2k" D2K_META_RANGES="$KILL/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_KILL_AFTER_ADD=1 \
    NDMC_STATE="$KILL/ndmc-state" NDMC_CALLS="$KILL/ndmc-calls" CURL_CALLS="$KILL/curl-calls" \
    D2K_INSTAGRAM_LOG="$KILL/refresh.log" sh "$SCRIPT" refresh; exit $?) 2>/dev/null; then
    fail "killed refresh reported success"
fi
added=$(awk '$1=="ip"&&$2=="host"&&$3!="unrelated.example"{print $3" "$4}' "$KILL/ndmc-state")
[ -n "$added" ] || fail "kill simulation did not add a record"
[ "$(cat "$KILL/d2k/state/instagram-ip-hosts.tsv" 2>/dev/null)" = "$added" ] || fail "pin added before the kill is not in the ownership manifest"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$KILL/d2k" NDMC_STATE="$KILL/ndmc-state" NDMC_CALLS="$KILL/ndmc-calls" \
    D2K_INSTAGRAM_LOG="$KILL/remove.log" sh "$SCRIPT" remove || fail "remove after an interrupted refresh failed"
[ "$(cat "$KILL/ndmc-state")" = 'ip host unrelated.example 192.0.2.7' ] || fail "interrupted refresh left an unowned pin"
ok "a refresh interrupted after an NDM add already owns that pin"

# A stop request (TERM from the scheduler during uninstall) while NDM is still
# applying an add: the helper lets that add finish, then exits without any
# further change, so the removal that follows sees and removes the pin.
STOP="$TMP/stopped"
mkdir -p "$STOP/d2k/state" "$STOP/d2k/files" "$STOP/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$STOP/d2k/files/"
printf 'ip host unrelated.example 192.0.2.7\n' > "$STOP/ndmc-state"
rc=0
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$STOP/d2k" D2K_META_RANGES="$STOP/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve NDMC_TERM_DURING_ADD=1 \
    NDMC_STATE="$STOP/ndmc-state" NDMC_CALLS="$STOP/ndmc-calls" CURL_CALLS="$STOP/curl-calls" \
    D2K_INSTAGRAM_LOG="$STOP/refresh.log" sh "$SCRIPT" refresh || rc=$?
[ "$rc" -ne 0 ] || fail "stopped refresh reported success"
[ "$(grep -c '^-c ip host ' "$STOP/ndmc-calls")" = 1 ] || fail "refresh continued adding after a stop request"
added=$(awk '$1=="ip"&&$2=="host"&&$3!="unrelated.example"{print $3" "$4}' "$STOP/ndmc-state")
[ -n "$added" ] || fail "helper exited before the in-flight NDM add finished"
[ "$(cat "$STOP/d2k/state/instagram-ip-hosts.tsv")" = "$added" ] || fail "in-flight add is not owned"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$STOP/d2k" NDMC_STATE="$STOP/ndmc-state" NDMC_CALLS="$STOP/ndmc-calls" \
    D2K_INSTAGRAM_LOG="$STOP/remove.log" sh "$SCRIPT" remove || fail "remove after a stopped refresh failed"
[ "$(cat "$STOP/ndmc-state")" = 'ip host unrelated.example 192.0.2.7' ] || fail "stopped refresh left an unowned pin"
ok "a stop request lets the in-flight NDM add finish, then exits; removal takes the pin back"

# A pair claimed by a refresh that died before NDM received it is dropped by
# the next refresh, so it can never cover the user's own later pin.
CLAIM="$TMP/claimed"
mkdir -p "$CLAIM/d2k/state" "$CLAIM/d2k/files" "$CLAIM/d2k/log"
cp "$TMP/d2k/files/meta-ranges.txt" "$CLAIM/d2k/files/"
: > "$CLAIM/ndmc-state"
printf 'graph.instagram.com 157.240.9.199\n' > "$CLAIM/d2k/state/instagram-ip-hosts.tsv"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$CLAIM/d2k" D2K_META_RANGES="$CLAIM/d2k/files/meta-ranges.txt" \
    D2K_RELAY_URL=https://resolve.example/resolve \
    NDMC_STATE="$CLAIM/ndmc-state" NDMC_CALLS="$CLAIM/ndmc-calls" CURL_CALLS="$CLAIM/curl-calls" \
    D2K_INSTAGRAM_LOG="$CLAIM/refresh.log" sh "$SCRIPT" refresh || fail "refresh with a stale claim failed"
! grep -q '^graph.instagram.com 157.240.9.199$' "$CLAIM/d2k/state/instagram-ip-hosts.tsv" || fail "claim of a pair absent from NDM survived a refresh"
printf 'ip host graph.instagram.com 157.240.9.199\n' >> "$CLAIM/ndmc-state"
env D2K_STUB_PATH="$TMP/bin" D2K_DIR="$CLAIM/d2k" NDMC_STATE="$CLAIM/ndmc-state" NDMC_CALLS="$CLAIM/ndmc-calls" \
    D2K_INSTAGRAM_LOG="$CLAIM/remove.log" sh "$SCRIPT" remove || fail "remove failed"
grep -q '^ip host graph.instagram.com 157.240.9.199$' "$CLAIM/ndmc-state" || fail "a stale claim removed the user's own later pin"
ok "a claim that never reached NDM is dropped at the next refresh"

echo "Instagram DNS lifecycle: all checks passed"
