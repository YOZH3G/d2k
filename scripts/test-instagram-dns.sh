#!/bin/sh
# Regression tests for the installer-owned Instagram static DNS lifecycle.
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

mkdir -p "$TMP/bin" "$TMP/d2k/state" "$TMP/d2k/files" "$TMP/d2k/log"
printf 'D2K_RESOLVE_SECRET="test-secret"\n' > "$TMP/d2k/config"
printf '157.240.0.0/16\n' > "$TMP/d2k/files/meta-ranges.txt"
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
        [ "${NDMC_FAIL_ADD:-0}" = 1 ] && exit 6
        printf '%s\n' "$*" >> "$NDMC_CALLS"
        printf 'ip host %s %s\n' "$(echo "$2" | awk '{print $3}')" "$(echo "$2" | awk '{print $4}')" >> "$NDMC_STATE"
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
        printf '{"results":{"instagram.com":["%s","8.8.8.8","%s","157.240.9.177","157.240.9.178"],"www.instagram.com":["157.240.9.175"],"not-instagram.example":["157.240.9.179"]}}' \
            "${VPS_IP1:-157.240.9.174}" "${VPS_IP2:-157.240.9.176}"
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
printf '%s' "$4" > "$OPENSSL_KEY"
cat >/dev/null
echo '(stdin)= 00ff'
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
grep -q 'X-Z2K-Auth: 00ff' "$TMP/curl-calls" || fail "VPS request omitted donor-compatible authentication header"
grep -q 'instagram.com.*www.instagram.com.*graph.instagram.com.*api.instagram.com.*instagram.c10r.instagram.com.*static.cdninstagram.com.*scontent.cdninstagram.com' "$TMP/curl-calls" || fail "VPS request did not contain the Instagram host set"
[ "$(cat "$TMP/openssl-key")" = test-secret ] || fail "quoted resolver secret was not parsed correctly"
grep -q -- '--check-instagram-ip instagram.com 157.240.9.174' "$TMP/curl-calls" || fail "DNS health still depends on blocked application HTTPS instead of certificate-verified edge health"
grep -q 'повтор TLS-пробы 1/2' "$TMP/refresh.log" || fail "transient IP probe failure was not retried"
ok "refresh pins VPS-verified Instagram IPs and records only D2K-owned pairs"

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

echo "Instagram DNS lifecycle: all checks passed"
