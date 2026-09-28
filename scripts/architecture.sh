#!/bin/sh
# Entware describes the userspace ABI; uname can describe a different kernel ABI.
set -eu
arch=${2:-${1:-}}
if [ "$arch" = mips ] && [ -z "${2:-}" ]; then
    echo 'uname=mips does not identify endianness; Entware ABI is required' >&2
    exit 1
fi
case "$arch" in
    aarch64|arm64|aarch64-*|arm64-*) echo arm64 ;;
    arm|armv7l|armv7|armv7-*|armv7sf-*|armv7hf-*|arm-*) echo arm ;;
    mips64el|mips64el-*|mipsel64|mipsel64-*) echo mips64el ;;
    mipsel|mipsel-*) echo mipsel ;;
    mips|mips-*) echo mips ;;
    x86_64|amd64|x64|x86_64-*|amd64-*|x64-*) echo amd64 ;;
    i686|x86|i686-*|x86-*) echo x86 ;;
    ppc64|ppc64-*) echo ppc64 ;;
    riscv64|riscv64-*) echo riscv64 ;;
    *) echo "Unsupported userspace architecture: $arch (uname=${1:-unknown})" >&2; exit 1 ;;
esac
