#!/bin/sh
# Run on Linux with qemu-user + binutils. Does not install or change networking.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
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
    for component in d2kd d2kc d2kpanel d2ktg; do
        bin="$ROOT/builds/$component-linux-$arch"
        test -s "$bin"
        readelf -h "$bin" >/dev/null
        if readelf -l "$bin" | grep -q INTERP || readelf -d "$bin" | grep -q NEEDED; then
            echo "Not a standalone static binary: $bin" >&2; exit 1
        fi
        case "$component" in
            d2kd) timeout 20 "qemu-$cpu" "$bin" --help >/dev/null 2>&1 ;;
            d2kc)
                rc=0
                timeout 20 "qemu-$cpu" "$bin" >/dev/null 2>&1 || rc=$?
                [ "$rc" = 2 ] || { echo "$bin: expected usage exit 2, got $rc" >&2; exit 1; }
                ;;
            *) timeout 20 "qemu-$cpu" "$bin" --version ;;
        esac
    done
    for test in crypto quicwire plan-parse openssl-link-smoke tg-session; do
        timeout 60 "qemu-$cpu" "$ROOT/build/telegram/$test-$arch"
    done
    case "$arch" in
        mips|mipsel) timeout 60 "qemu-$cpu" -cpu 4Kc "$ROOT/build/telegram/tg-session-$arch" ;;
        x86) timeout 60 "qemu-$cpu" -cpu pentium2 "$ROOT/build/telegram/tg-session-$arch" ;;
    esac
    echo "$arch: static executables + startup + crypto/wire/plan/OpenSSL tests PASS"
done
