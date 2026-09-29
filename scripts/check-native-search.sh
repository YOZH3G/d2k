#!/bin/sh
# Autonomous native IPv6 TLS search against a packet-string lab censor.
# Empty catalog, real curl ClientHello, independent TLS server, restart proof.
# Docker only: no router or public application traffic. Not field acceptance.
set -eu
if [ "${1:-}" != --inside ]; then
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    WORK=$(mktemp -d /tmp/d2k-native-search.XXXXXX)
    # Keep bounded lab evidence after the disposable container exits.
    echo "Native search artifacts: $WORK"
    cd "$ROOT"
    tar -cf - --exclude='*.o' --exclude='test_*' core datapath detect spike/labtls.c \
        scripts/check-native-search.sh | tar -C "$WORK" -xf -
    docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
        -v "$WORK:/w" -w /w gcc:14 sh scripts/check-native-search.sh --inside
    exit
fi
apt-get update -qq
apt-get install -y -qq iptables iproute2 ethtool curl libssl-dev >/dev/null
make -s -C datapath d2kd
make -s -C core d2kc
cc -std=c99 -O2 -Wall -Wextra -Werror -o /tmp/labtls spike/labtls.c -lssl -lcrypto
mkdir -p /w/evidence
ip -6 addr add fd42:d2:6::1/128 dev lo nodad
ip link set lo mtu 1500
ethtool -K lo gro off gso off tso off >/dev/null
printf '%s\n' 'fd42:d2:6::1 blocked.example control.example' >> /etc/hosts
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -nodes \
    -subj /CN=blocked.example \
    -addext subjectAltName=DNS:blocked.example,DNS:control.example >/dev/null 2>&1
/tmp/labtls 4443 /tmp/cert.pem /tmp/key.pem 6 > /w/evidence/server.log 2>&1 &
server=$!
dp='' cp=''
cleanup() {
    [ -z "$cp" ] || kill "$cp" 2>/dev/null || true
    [ -z "$dp" ] || kill "$dp" 2>/dev/null || true
    kill "$server" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
client() {
    curl --noproxy '*' -6 -fsS --connect-timeout 2 --max-time 4 \
        --tlsv1."$version" --tls-max 1."$version" --cacert /tmp/cert.pem \
        "https://$1:4443/" 2>/w/evidence/client.err
}
version=3
i=0
until [ "$(client control.example || true)" = ok ]; do
    i=$((i + 1)); [ "$i" -lt 5 ] || { echo 'native TLS server unavailable'; exit 1; }
    sleep 0.2
done
ip6tables -t mangle -N D2K_NATIVE
ip6tables -t mangle -A OUTPUT -j D2K_NATIVE
# Register conntrack in this fresh namespace, as the router's firewall does.
# A proc table can exist but remain empty when no conntrack match is loaded.
ip6tables -t mangle -A D2K_NATIVE -m conntrack --ctstate INVALID -j RETURN
ip6tables -t mangle -A D2K_NATIVE -m mark --mark 45 -j RETURN
ip6tables -t mangle -A D2K_NATIVE -m mark --mark 47 -j RETURN
ip6tables -t mangle -A D2K_NATIVE -p tcp --dport 4443 \
    -j NFQUEUE --queue-num 2301 --queue-bypass
ip6tables -t mangle -A INPUT -p tcp --sport 4443 -m mark ! --mark 45 \
    -j NFQUEUE --queue-num 2301 --queue-bypass
ip6tables -t mangle -A PREROUTING -p tcp --dport 4443 \
    -m string --string blocked.example --algo bm -j DROP
start_engine() {
    ./datapath/d2kd --mode apply --control "$sock" --queue 2301 --mark 45 \
        --probe-mark 46 --journal 400 --duration 240 >"$prefix-datapath.log" 2>&1 &
    dp=$!
    i=0
    while [ ! -S "$sock" ]; do
        kill -0 "$dp"
        i=$((i + 1)); [ "$i" -lt 100 ]; sleep 0.05
    done
    ./core/d2kc --control "$sock" --catalog "$catalog" --mark 46 --measure-mark 47 \
        >"$prefix-controller.log" 2>&1 &
    cp=$!
}
stop_engine() {
    kill "$cp"; wait "$cp" || true; cp=
    kill "$dp"; wait "$dp" || true; dp=
}
for version in 2 3; do
    prefix=/w/evidence/tls1$version
    sock=/tmp/native-tls1$version.sock
    catalog=$prefix-catalog.json
    [ ! -e "$catalog" ]
    [ "$(client control.example)" = ok ]
    if client blocked.example >/dev/null; then
        echo 'censor did not block the independent client'; exit 1
    fi
    start_engine
    worked=0
    for attempt in $(seq 1 60); do
        echo "TLS 1.$version native client attempt $attempt"
        kill -0 "$cp" "$dp"
        if [ "$(client blocked.example || true)" = ok ]; then worked=1; break; fi
        sleep 1
    done
    if [ "$worked" != 1 ]; then
        tail -n 50 "$prefix-controller.log" "$prefix-datapath.log"
        echo "TLS 1.$version autonomous IPv6 search failed"; exit 1
    fi
    stop_engine
    [ -s "$catalog" ]
    cp "$catalog" "$prefix-before-restart.json"
    prefix=$prefix-restart
    start_engine
    sleep 2
    [ "$(client blocked.example)" = ok ]
    [ "$(client control.example)" = ok ]
    stop_engine
    echo "TLS 1.$version: native block -> autonomous search -> content -> restart passed"
done
ip6tables -t mangle -L -nv > /w/evidence/firewall.txt
