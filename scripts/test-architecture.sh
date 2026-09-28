#!/bin/sh
# Wrong endian/ABI selection must fail before downloading or stopping services.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
check() {
    got=$(sh "$ROOT/scripts/architecture.sh" "$1" "$2")
    [ "$got" = "$3" ] || { echo "$1 / $2: expected $3, got $got" >&2; exit 1; }
}
check aarch64 '' arm64
check armv7l armv7-3.2 arm
check mips mipsel-3.4 mipsel
check mips mips-3.4 mips
check mips64 mipsel-3.4 mipsel
check mips64 mips64el-3.4 mips64el
check mips64el '' mips64el
check x86_64 '' amd64
check x86_64 x64-3.2 amd64
check aarch64 aarch64-3.10_kn arm64
check armv7l armv7-3.2_kn arm
check mips mipsel-3.4_kn mipsel
check x86_64 i686 x86
check i686 '' x86
check ppc64 '' ppc64
check riscv64 '' riscv64
for arch in armv5tel armv6l armv7b i386 i486 i586 lexra ppc ppc64le mips mips64 sparc unknown; do
    if sh "$ROOT/scripts/architecture.sh" "$arch" '' >/dev/null 2>&1; then
        echo "unsupported $arch accepted" >&2; exit 1
    fi
done
if sh "$ROOT/scripts/architecture.sh" mips strange-feed >/dev/null 2>&1; then
    echo 'unknown Entware ABI silently ignored' >&2; exit 1
fi
echo 'architecture selection: PASS'
if printf 'cpu model : MIPS 64Kc V1.0\n' | sh "$ROOT/scripts/check-cpu.sh" mips64el /dev/stdin; then
    echo 'MIPS64 without FPU accepted' >&2; exit 1
fi
printf 'cpu model : MIPS 64Kf V1.0 FPU V1.0\n' | sh "$ROOT/scripts/check-cpu.sh" mips64el /dev/stdin
sh "$ROOT/scripts/check-cpu.sh" mipsel /does-not-exist
if printf 'Features : swp half thumb vfp\n' | sh "$ROOT/scripts/check-cpu.sh" arm /dev/stdin; then
    echo 'ARM without required VFPv3 accepted' >&2; exit 1
fi
printf 'Features : half thumb vfpv3 tls\n' | sh "$ROOT/scripts/check-cpu.sh" arm /dev/stdin
printf 'Features : fp asimd aes\n' | sh "$ROOT/scripts/check-cpu.sh" arm /dev/stdin
echo 'CPU capability gate: PASS'
