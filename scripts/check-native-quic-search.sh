#!/bin/sh
# Native IPv6 QUIC lifecycle with independent aioquic HTTP/3 endpoints.
# Isolated Docker namespace only; the toy first-datagram censor is not field DPI.
set -eu
if [ "${1:-}" != --inside ]; then
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    WORK=$(mktemp -d /tmp/d2k-native-quic.XXXXXX)
    echo "Native QUIC artifacts: $WORK"
    cd "$ROOT"
    tar -cf - --exclude='*.o' --exclude='test_*' core datapath detect \
        spike/labdpi.c tests/native-h3-server.py tests/native-h3-client.py \
        scripts/check-native-quic-search.sh | tar -C "$WORK" -xf -
    docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW \
        -v "$WORK:/w" -w /w gcc:14 sh scripts/check-native-quic-search.sh --inside
    exit
fi
apt-get update -qq
apt-get install -y -qq iptables iproute2 openssl python3-aioquic >/dev/null
make -s -C datapath d2kd
make -s -C core d2kc
cc -std=c99 -O2 -Wall -Wextra -Werror -Idatapath/include -Icore/include \
    -o /tmp/labdpi spike/labdpi.c datapath/nfq.c datapath/nl.c \
    core/quic.c core/quicwire.c core/crypto.c
mkdir -p /w/evidence
# Documentation prefix, routed only to loopback inside this namespace.
ip -6 addr add 2001:db8:d2::1/128 dev lo nodad
ip link set lo mtu 1500
printf '%s\n' '2001:db8:d2::1 blocked.example control.example' >> /etc/hosts
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -nodes \
    -subj /CN=blocked.example \
    -addext subjectAltName=DNS:blocked.example,DNS:control.example >/dev/null 2>&1
python3 tests/native-h3-server.py /tmp/cert.pem /tmp/key.pem 2001:db8:d2::1 \
    > /w/evidence/server.log 2>&1 &
server=$!
censor='' dp='' cp=''
cleanup() {
    for pid in "$cp" "$dp" "$censor" "$server"; do
        [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM
i=0
while ! grep -q 'HTTP/3 ready' /w/evidence/server.log; do
    kill -0 "$server"
    i=$((i + 1)); [ "$i" -lt 100 ]; sleep 0.05
done
client() {
    python3 tests/native-h3-client.py 2001:db8:d2::1 4444 "$1" /tmp/cert.pem \
        2>/w/evidence/client.err
}
client blocked.example
ip6tables -t mangle -A OUTPUT -m conntrack --ctstate INVALID -j RETURN
/tmp/labdpi 2402 blocked.example 62 --quic --first > /w/evidence/censor.log 2>&1 &
censor=$!
i=0
while ! grep -q 'labdpi: очередь' /w/evidence/censor.log; do
    kill -0 "$censor"
    i=$((i + 1)); [ "$i" -lt 100 ]; sleep 0.05
done
ip6tables -t mangle -A PREROUTING -p udp --dport 4444 \
    -j NFQUEUE --queue-num 2402 --queue-bypass
if client blocked.example; then
    echo 'FAIL: native QUIC censor did not block the independent client'; exit 1
fi
client control.example
ip6tables -t mangle -N D2K_NATIVE_QUIC
ip6tables -t mangle -A OUTPUT -j D2K_NATIVE_QUIC
ip6tables -t mangle -A D2K_NATIVE_QUIC -m mark --mark 45 -j RETURN
ip6tables -t mangle -A D2K_NATIVE_QUIC -m mark --mark 47 -j RETURN
ip6tables -t mangle -A D2K_NATIVE_QUIC -p udp --dport 4444 \
    -j NFQUEUE --queue-num 2401 --queue-bypass
ip6tables -t mangle -A INPUT -p udp --sport 4444 \
    -j NFQUEUE --queue-num 2401 --queue-bypass
prefix=/w/evidence/quic
catalog=/w/evidence/catalog.json
start_engine() {
    ./datapath/d2kd --mode apply --control /tmp/native-quic.sock --queue 2401 \
        --mark 45 --probe-mark 46 --udp-reverse-hook --duration 300 --journal 400 \
        >"$prefix-datapath.log" 2>&1 &
    dp=$!
    i=0
    while [ ! -S /tmp/native-quic.sock ]; do
        kill -0 "$dp"
        i=$((i + 1)); [ "$i" -lt 100 ]; sleep 0.05
    done
    ./core/d2kc --control /tmp/native-quic.sock --catalog "$catalog" \
        --mark 46 --measure-mark 47 >"$prefix-controller.log" 2>&1 &
    cp=$!
}
stop_engine() {
    kill "$cp"; wait "$cp" || true; cp=''
    kill "$dp"; wait "$dp" || true; dp=''
}
start_engine
worked=0
for attempt in $(seq 1 40); do
    kill -0 "$cp" "$dp" "$censor"
    echo "QUIC native client attempt $attempt"
    if client blocked.example; then worked=1; break; fi
    sleep 1
done
if [ "$worked" != 1 ]; then
    tail -n 40 "$prefix-controller.log" "$prefix-datapath.log"
    echo 'FAIL: autonomous native QUIC search'; exit 1
fi
stop_engine
[ -s "$catalog" ]
cp "$catalog" /w/evidence/before-restart.json
prefix=/w/evidence/quic-restart
start_engine
sleep 2
client blocked.example
client control.example
stop_engine
kill "$censor"; wait "$censor" || true; censor=''
cat /w/evidence/censor.log
ip6tables -t mangle -L -nv > /w/evidence/firewall.txt
echo 'QUIC: native block -> autonomous search -> HTTP/3 content -> restart passed'
