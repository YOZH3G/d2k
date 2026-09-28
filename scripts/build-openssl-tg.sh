#!/bin/sh
set -eu

# OpenSSL source is fetched at an immutable upstream commit, then built into a
# static musl archive for the only currently supported router architecture.
OPENSSL_COMMIT=f4dc4d58b48d346a8270183f89acf826d459b0ca
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ZIG=${ZIG:-zig}
JOBS=${JOBS:-4}
SRC_DIR=${OPENSSL_SRC_DIR:-"$ROOT/build/telegram/openssl-src"}
PREFIX=${OPENSSL_PREFIX:-"$ROOT/build/telegram/openssl-arm64"}

command -v "$ZIG" >/dev/null 2>&1 || { echo "zig not found: $ZIG" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required to fetch pinned OpenSSL" >&2; exit 1; }
mkdir -p "$(dirname -- "$SRC_DIR")" "$PREFIX"
mkdir -p "$ROOT/build/telegram"

if [ ! -d "$SRC_DIR/.git" ]; then
    git clone --filter=blob:none https://github.com/openssl/openssl.git "$SRC_DIR"
fi
actual=$(git -C "$SRC_DIR" rev-parse HEAD)
if [ "$actual" != "$OPENSSL_COMMIT" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$OPENSSL_COMMIT"
    git -C "$SRC_DIR" checkout --detach "$OPENSSL_COMMIT"
fi
[ "$(git -C "$SRC_DIR" rev-parse HEAD)" = "$OPENSSL_COMMIT" ] || {
    echo "OpenSSL source revision mismatch" >&2
    exit 1
}

cd "$SRC_DIR"
CC="$ZIG cc -target aarch64-linux-musl" \
AR="$ZIG ar" RANLIB="$ZIG ranlib" \
    ./Configure linux-aarch64 no-shared no-tests no-apps no-docs no-legacy \
    --prefix="$PREFIX" --openssldir=/opt/d2k/certs
make -j "$JOBS" build_libs
make install_sw

SMOKE="$ROOT/telegram/test_openssl_link.c"
LIBDIR="$PREFIX/lib"
[ -d "$LIBDIR" ] || LIBDIR="$PREFIX/lib64"
"$ZIG" cc -target aarch64-linux-musl -static \
    -I"$PREFIX/include" -L"$LIBDIR" \
    -o "$ROOT/build/telegram/openssl-link-smoke" "$SMOKE" \
    -lssl -lcrypto -ldl -pthread
file "$ROOT/build/telegram/openssl-link-smoke"

# The router runtime is a single static C executable. Keep all implementation
# sources in the compile command so the package cannot accidentally omit a
# newly added module.
"$ZIG" cc -target aarch64-linux-musl -static -O2 -std=c11 \
    -Wall -Wextra -Werror -pedantic -Wl,-S \
    -I"$ROOT/telegram/include" -I"$PREFIX/include" \
    -o "$ROOT/builds/d2ktg-linux-arm64" "$ROOT"/telegram/src/*.c \
    -L"$LIBDIR" -lssl -lcrypto -ldl -pthread
file "$ROOT/builds/d2ktg-linux-arm64"
