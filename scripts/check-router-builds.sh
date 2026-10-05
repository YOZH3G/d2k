#!/bin/sh
# Run on Linux with qemu-user + binutils; Node.js is also needed for the
# controller/datapath handshake on MIPS. Does not install or change networking.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
OUT=${OUT:-"$ROOT/builds"}
TEST_OUT=${TEST_OUT:-"$OUT/tests"}
: "${RELEASE_ID:?common release identity required}"
: "${SOURCE_DATE_EPOCH:?build epoch required}"
ADAPTER_ROOT=$(mktemp -d)
chmod 755 "$ADAPTER_ROOT"
trap 'rmdir "$ADAPTER_ROOT" 2>/dev/null || true' EXIT
for arch in $ARCHES; do
    case "$arch" in
        arm64) cpu=aarch64 ;;
        arm) cpu=arm ;;
        mipsel) cpu=mipsel ;;
        mips) cpu=mips ;;
        mips64el) cpu=mips64el ;;
        amd64) cpu=x86_64 ;;
        x86) cpu=i386 ;;
        ppc64) cpu=ppc64 ;;
        riscv64) cpu=riscv64 ;;
        *) echo "Unknown architecture: $arch" >&2; exit 1 ;;
    esac
    for component in d2kd d2kc d2kpanel d2ktg d2k-update d2k-update-boot d2k-service-adapter; do
        bin="$OUT/$component-linux-$arch"
        test -s "$bin"
        readelf -h "$bin" >/dev/null
        if readelf -l "$bin" | grep -q INTERP || readelf -d "$bin" | grep -q NEEDED; then
            echo "Not a standalone static binary: $bin" >&2; exit 1
        fi
        case "$component" in
            d2k-update-boot) [ "$(timeout 20 "qemu-$cpu" "$bin" --boot-protocol)" = 1 ] ;;
            d2k-service-adapter)
                # The adapter refuses a missing or foreign root (exit 1) before
                # it reads the action, and /opt/d2k does not exist here: give
                # it an owned empty root so the usage exit proves startup.
                rc=0; timeout 20 "qemu-$cpu" "$bin" --root "$ADAPTER_ROOT" >/dev/null 2>&1 || rc=$?
                [ "$rc" = 2 ] || { echo "$bin: expected usage exit 2, got $rc" >&2; exit 1; }
                ;;
            *) [ "$(timeout 20 "qemu-$cpu" "$bin" --release-id)" = "$RELEASE_ID" ] ;;
        esac
        case "$component" in
            d2k-update|d2k-update-boot|d2k-service-adapter) : ;;
            d2kd) timeout 20 "qemu-$cpu" "$bin" --help >/dev/null 2>&1 ;;
            d2kc)
                rc=0
                timeout 20 "qemu-$cpu" "$bin" >/dev/null 2>&1 || rc=$?
                [ "$rc" = 2 ] || { echo "$bin: expected usage exit 2, got $rc" >&2; exit 1; }
                ;;
            *) timeout 20 "qemu-$cpu" "$bin" --version ;;
        esac
    done
    for test in crypto quicwire plan-parse openssl-link-smoke tg-session curl-link-smoke update-manifest update-package update-schedule; do
        timeout 60 "qemu-$cpu" "$TEST_OUT/$test-$arch"
    done
    (cd "$ROOT/telegram" && timeout 120 "qemu-$cpu" "$TEST_OUT/tg-tls-$arch")
    variant=
    case "$arch" in
        mips|mipsel) variant=4Kc ;;
        x86) variant=pentium2 ;;
    esac
    if [ -n "$variant" ]; then
        for test in openssl-link-smoke curl-link-smoke tg-session update-manifest update-package update-schedule; do
            timeout 120 "qemu-$cpu" -cpu "$variant" "$TEST_OUT/$test-$arch"
        done
        (cd "$ROOT/telegram" && timeout 180 "qemu-$cpu" -cpu "$variant" "$TEST_OUT/tg-tls-$arch")
    fi
    case "$arch" in
        mips|mipsel)
            command -v node >/dev/null 2>&1 || {
                echo "node is required for the MIPS controller startup regression" >&2
                exit 1
            }
            D2K_TEST_BINARY="$OUT/d2kc-linux-$arch" \
            D2K_TEST_RELEASE_ID="$RELEASE_ID" \
            D2K_TEST_RUNNER="qemu-$cpu" \
            D2K_TEST_RUNNER_ARGS='-cpu 24Kc' \
                node "$ROOT/scripts/test-controller-handshake.cjs"
            ;;
    esac
    python3 "$ROOT/scripts/update_release_provenance.py" --root "$ROOT" --build-dir "$OUT" \
        --abi "$arch" --release "$RELEASE_ID" --built-at "$SOURCE_DATE_EPOCH" --gates
    echo "$arch: static executables + startup + crypto/wire/plan/OpenSSL tests PASS"
done
