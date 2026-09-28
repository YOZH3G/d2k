#!/bin/sh
# Sourced by release builders. Nine complete router targets from z2k's matrix.
# shellcheck disable=SC2034
ARCH=${ARCH:-arm64}
BUILD_ZIG=${ZIG:-zig}
TARGET_FLAGS=
case "$ARCH" in
    arm64) TARGET=aarch64-linux-musl; SSL_TARGET=linux-aarch64 ;;
    arm) TARGET=arm-linux-musleabi; TARGET_FLAGS=-mcpu=generic+v7a; SSL_TARGET=linux-armv4 ;;
    mipsel) TARGET=mipsel-linux-musleabi; TARGET_FLAGS=-mcpu=mips32+soft_float; SSL_TARGET=linux-mips32 ;;
    mips) TARGET=mips-linux-musleabi; TARGET_FLAGS=-mcpu=mips32+soft_float; SSL_TARGET=linux-mips32 ;;
    mips64el)
        TARGET=mips64el-linux-muslabi64; TARGET_FLAGS='-mcpu=mips64 -fPIC'; SSL_TARGET=linux64-mips64
        BUILD_ZIG=${ZIG_MIPS64EL:-$BUILD_ZIG}
        ;;
    amd64) TARGET=x86_64-linux-musl; TARGET_FLAGS=-mcpu=x86_64; SSL_TARGET=linux-x86_64 ;;
    x86) TARGET=x86-linux-musl; TARGET_FLAGS=-mcpu=i686; SSL_TARGET=linux-x86 ;;
    ppc64) TARGET=powerpc64-linux-musl; SSL_TARGET=linux-ppc64 ;;
    riscv64) TARGET=riscv64-linux-musl; SSL_TARGET=linux64-riscv64 ;;
    *) echo "Unsupported build architecture: $ARCH" >&2; exit 1 ;;
esac
