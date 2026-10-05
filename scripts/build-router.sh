#!/bin/sh
# Complete C-only installable packages. Each architecture has isolated SSL objects.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCHES=${ARCHES:-"arm64 arm mipsel mips mips64el amd64 x86 ppc64 riscv64"}
OUT=${OUT:-"$ROOT/builds"}
mkdir -p "$OUT"
OUT=$(CDPATH='' cd -- "$OUT" && pwd)
ZIG=${ZIG:-zig}
COMMIT=$(git -C "$ROOT" rev-parse HEAD)
: "${RELEASE_ID:?explicit common RELEASE_ID required}"
: "${SOURCE_DATE_EPOCH:?explicit deterministic build epoch required}"
: "${DEPS_PROVENANCE:?validated dependency receipt path required}"
python3 - "$ROOT/scripts" "$ROOT" "$RELEASE_ID" <<'CHECK'
import sys
sys.path.insert(0,sys.argv[1])
from update_release_provenance import clean_source
import importlib.util
spec=importlib.util.spec_from_file_location('package',sys.argv[1]+'/package-update.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
clean_source(sys.argv[2]);m.release_id(sys.argv[3])
CHECK
TEST_OUT=${TEST_OUT:-"$OUT/tests"}
mkdir -p "$TEST_OUT"
export TEST_OUT RELEASE_ID DEPS_PROVENANCE

BUILT=$(python3 -c 'import datetime,os;print(datetime.datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]),datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
DIRTY=0
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || DIRTY=1
for ARCH in $ARCHES; do
    . "$ROOT/scripts/build-target.sh"
    eval "$(python3 "$ROOT/scripts/update_release_provenance.py" --root "$ROOT" --build-dir "$OUT" --abi "$ARCH" --dependencies "$DEPS_PROVENANCE" --deps-env)"
    echo "=== $ARCH ($TARGET $TARGET_FLAGS) ==="
    for component in datapath core panel; do
        make -C "$ROOT/$component" release ARCH="$ARCH" TARGET="$TARGET" \
            TARGET_FLAGS="$TARGET_FLAGS" ZIG="$BUILD_ZIG" BUILDDIR="$OUT" \
            COMMIT="$COMMIT" BUILT="$BUILT" DIRTY="$DIRTY" RELEASE_ID="$RELEASE_ID" VERSION="${VERSION:-0.1.0-mvp}"
    done
    ARCH="$ARCH" ZIG="$BUILD_ZIG" OUT="$OUT" sh "$ROOT/scripts/build-openssl-tg.sh"
    ssl_lib="$OPENSSL_PREFIX/lib"
    [ -f "$ssl_lib/libssl.a" ] || ssl_lib="$OPENSSL_PREFIX/lib64"
    cc="$BUILD_ZIG cc -target $TARGET $TARGET_FLAGS"
    make -C "$ROOT/update" daemon boot service-adapter BUILD="$OUT/update-$ARCH" \
        CC="$cc" CFLAGS="-static -Os -std=c11 -Wall -Wextra -Werror -pedantic -pthread -ffunction-sections -fdata-sections -Wl,--gc-sections" \
        CPPFLAGS="-Iinclude -I$OPENSSL_PREFIX/include" CURL_CFLAGS="-I$UPDATE_DEPS_PREFIX/include" \
        LDLIBS="-Wl,--start-group $ssl_lib/libssl.a $ssl_lib/libcrypto.a $UPDATE_DEPS_PREFIX/lib/libcurl.a -Wl,--end-group -ldl -pthread" \
        CURL_LIBS="" RELEASE_ID="$RELEASE_ID"
    for component in d2k-update d2k-update-boot d2k-service-adapter; do
        cp "$OUT/update-$ARCH/$component" "$OUT/$component-linux-$ARCH"
    done
    cp "$DEPENDENCY_CURL_SMOKE" "$TEST_OUT/curl-link-smoke-$ARCH"
    python3 "$ROOT/scripts/update_release_provenance.py" --root "$ROOT" --build-dir "$OUT" \
        --abi "$ARCH" --release "$RELEASE_ID" --built-at "$SOURCE_DATE_EPOCH" \
        --dependencies "$DEPS_PROVENANCE" --record
done
