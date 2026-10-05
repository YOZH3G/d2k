#!/bin/sh
# Cross-build existing byte-level regression tests, using release CPU/ABI flags.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ZIG=${ZIG:-zig}
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
OUT=${TEST_OUT:-"${OUT:-$ROOT/builds}/tests"}
: "${DEPS_PROVENANCE:?validated dependency receipt path required}"
mkdir -p "$OUT"
for ARCH in $ARCHES; do
    . "$ROOT/scripts/build-target.sh"
    eval "$(python3 "$ROOT/scripts/update_release_provenance.py" --root "$ROOT" --build-dir "$OUT" --abi "$ARCH" --dependencies "$DEPS_PROVENANCE" --deps-env)"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c99 \
        -I"$ROOT/core/include" -I"$ROOT/datapath/include" \
        "$ROOT/core/test_crypto.c" "$ROOT/core/crypto.c" -o "$OUT/crypto-$ARCH"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c99 \
        -I"$ROOT/core/include" -I"$ROOT/datapath/include" \
        "$ROOT/core/test_quicwire.c" "$ROOT/core/quicwire.c" "$ROOT/core/crypto.c" \
        -o "$OUT/quicwire-$ARCH"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c99 \
        -I"$ROOT/core/include" -I"$ROOT/datapath/include" \
        "$ROOT/datapath/test_plan_parse.c" "$ROOT/datapath/plan_parse.c" \
        -o "$OUT/plan-parse-$ARCH"
    prefix="$OPENSSL_PREFIX"
    libdir="$prefix/lib"
    [ -d "$libdir" ] || libdir="$prefix/lib64"
    # Includes retry jitter (floating-point on soft-float MIPS) and identity crypto.
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c11 \
        -I"$ROOT/telegram/include" -I"$prefix/include" \
        "$ROOT/telegram/test_session.c" "$ROOT/telegram/src/session.c" \
        "$ROOT/telegram/src/wire.c" "$ROOT/telegram/src/identity.c" \
        -L"$libdir" -lssl -lcrypto -ldl -pthread -o "$OUT/tg-session-$ARCH"
    # shellcheck disable=SC2086
    "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c11 \
        -I"$ROOT/telegram/include" -I"$prefix/include" \
        "$ROOT/telegram/test_tls.c" \
        "$ROOT/telegram/src/tls.c" "$ROOT/telegram/src/ws.c" "$ROOT/telegram/src/ws_pump.c" \
        "$ROOT/telegram/src/identity.c" "$ROOT/telegram/src/register.c" "$ROOT/telegram/src/enroll.c" \
        "$ROOT/telegram/src/net.c" "$ROOT/telegram/src/wire.c" "$ROOT/telegram/src/tunnel.c" \
        "$ROOT/telegram/src/listener.c" "$ROOT/telegram/src/streams.c" "$ROOT/telegram/src/queue.c" \
        "$ROOT/telegram/src/session.c" -L"$libdir" -lssl -lcrypto -ldl -pthread -o "$OUT/tg-tls-$ARCH"
    for test in manifest package schedule; do
        # shellcheck disable=SC2086
        "$BUILD_ZIG" cc -target "$TARGET" $TARGET_FLAGS -static -O2 -UNDEBUG -std=c11 \
            -D_POSIX_C_SOURCE=200809L -I"$ROOT/update/include" -I"$prefix/include" \
            "$ROOT/update/tests/test_$test.c" "$ROOT/update/src/$test.c" \
            -L"$libdir" -lssl -lcrypto -ldl -pthread -o "$OUT/update-$test-$ARCH"
    done
done
