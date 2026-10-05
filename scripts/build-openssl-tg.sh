#!/bin/sh
set -eu

# OpenSSL source is fetched at an immutable upstream commit, then built into a
# static musl archive for the selected router architecture.
OPENSSL_COMMIT=f4dc4d58b48d346a8270183f89acf826d459b0ca
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/build-target.sh"
ZIG=$BUILD_ZIG
JOBS=${JOBS:-4}
SRC_DIR=${OPENSSL_SRC_DIR:-"$ROOT/build/telegram/openssl-src"}
PREFIX=${OPENSSL_PREFIX:-"$ROOT/build/telegram/openssl-$ARCH"}
OBJ_DIR=${OPENSSL_OBJ_DIR:-"$ROOT/build/telegram/obj-$ARCH"}
OUT=${OUT:-"$ROOT/builds"}
TEST_OUT=${TEST_OUT:-"$ROOT/build/telegram"}

command -v "$ZIG" >/dev/null 2>&1 || { echo "zig not found: $ZIG" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required to fetch pinned OpenSSL" >&2; exit 1; }
mkdir -p "$(dirname -- "$SRC_DIR")" "$PREFIX"
mkdir -p "$TEST_OUT" "$OUT"
if [ "${D2K_REUSE_VALIDATED_DEPS:-0}" = 1 ]; then
    : "${DEPS_PROVENANCE:?validated receipt required for dependency reuse}"
    python3 "$ROOT/scripts/update_release_provenance.py" --root "$ROOT" --build-dir "$OUT" \
        --abi "$ARCH" --dependencies "$DEPS_PROVENANCE" --deps-env >/dev/null
else
mkdir -p "$OBJ_DIR"

if [ ! -d "$SRC_DIR/.git" ]; then
    git init "$SRC_DIR"
    git -C "$SRC_DIR" remote add origin https://github.com/openssl/openssl.git
fi
actual=$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || true)
if [ "$actual" != "$OPENSSL_COMMIT" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$OPENSSL_COMMIT"
    git -C "$SRC_DIR" checkout --detach "$OPENSSL_COMMIT"
fi
[ "$(git -C "$SRC_DIR" rev-parse HEAD)" = "$OPENSSL_COMMIT" ] || {
    echo "OpenSSL source revision mismatch" >&2
    exit 1
}

cd "$OBJ_DIR"
ASM_FLAGS=no-asm
case "$ARCH" in arm64|amd64) ASM_FLAGS= ;; esac
ATOMIC_FLAGS=
# 32-bit targets may not provide lock-free, unaligned 64-bit atomics. Use OpenSSL's existing
# pthread-lock fallback rather than requiring a router-side libatomic.
case "$ARCH" in mips|mipsel|x86) ATOMIC_FLAGS=-DBROKEN_CLANG_ATOMICS ;; esac
# shellcheck disable=SC2086
CC="$ZIG cc -target $TARGET $TARGET_FLAGS" \
AR="$ZIG ar" RANLIB="$ZIG ranlib" \
    "$SRC_DIR/Configure" "$SSL_TARGET" no-shared no-tests no-apps no-docs no-legacy $ASM_FLAGS $ATOMIC_FLAGS \
    --prefix="$PREFIX" --openssldir=/opt/d2k/certs
make -j "$JOBS" build_libs
make install_sw
[ -z "$(git -C "$SRC_DIR" status --porcelain --untracked-files=all)" ] || { echo "OpenSSL source dirty" >&2; exit 1; }
fi

SMOKE="$ROOT/telegram/test_openssl_link.c"
LIBDIR="$PREFIX/lib"
[ -d "$LIBDIR" ] || LIBDIR="$PREFIX/lib64"
# TARGET_FLAGS is a controlled compiler option from build-target.sh.
# shellcheck disable=SC2086
"$ZIG" cc -target "$TARGET" $TARGET_FLAGS -static \
    -I"$PREFIX/include" -L"$LIBDIR" \
    -o "$TEST_OUT/openssl-link-smoke-$ARCH" "$SMOKE" \
    -lssl -lcrypto -ldl -pthread
file "$TEST_OUT/openssl-link-smoke-$ARCH"

# The router runtime is a single static C executable. Keep all implementation
# sources in the compile command so the package cannot accidentally omit a
# newly added module.
# shellcheck disable=SC2086
"$ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -std=c11 \
    -Wall -Wextra -Werror -pedantic -Wl,-S \
    -DD2K_RELEASE_ID="\"${RELEASE_ID:-dev}\"" \
    -I"$ROOT/telegram/include" -I"$PREFIX/include" \
    -o "$OUT/d2ktg-linux-$ARCH" "$ROOT"/telegram/src/*.c \
    -L"$LIBDIR" -lssl -lcrypto -ldl -pthread
file "$OUT/d2ktg-linux-$ARCH"
