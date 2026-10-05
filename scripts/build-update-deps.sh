#!/bin/sh
# Local build only: immutable HTTPS libcurl + existing pinned static OpenSSL.
# ARCH follows build-target.sh; this script never installs on a router.
set -eu
CURL_VERSION=8.22.0
CURL_COMMIT=01346829096c61b372692f6dc43ffa778c6caccd
CURL_SHA256=f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7
OPENSSL_COMMIT=f4dc4d58b48d346a8270183f89acf826d459b0ca
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/build-target.sh"
D2KU_ZIG=$(command -v "$BUILD_ZIG")
D2KU_TARGET=$TARGET
D2KU_TARGET_FLAGS=$TARGET_FLAGS
export D2KU_ZIG D2KU_TARGET D2KU_TARGET_FLAGS
DEPS_DIR=${UPDATE_DEPS_DIR:-"$ROOT/build/update-deps"}
PREFIX=${UPDATE_DEPS_PREFIX:-"$DEPS_DIR/curl-$ARCH"}
SSL_PREFIX=${OPENSSL_PREFIX:-"$ROOT/build/telegram/openssl-$ARCH"}
SSL_SOURCE=${OPENSSL_SRC_DIR:-"$ROOT/build/telegram/openssl-src"}
JOBS=${JOBS:-4}
command -v cmake >/dev/null
[ "$(git -C "$SSL_SOURCE" rev-parse HEAD)" = "$OPENSSL_COMMIT" ] || { echo 'Pinned OpenSSL source missing/mismatched; run build-openssl-tg.sh first' >&2; exit 1; }
# Source must not carry local modifications into the dependency provenance.
[ -z "$(git -C "$SSL_SOURCE" status --porcelain --untracked-files=all)" ] || { echo 'OpenSSL source is dirty' >&2; exit 1; }
SSL_LIB="$SSL_PREFIX/lib"
[ -f "$SSL_LIB/libssl.a" ] || SSL_LIB="$SSL_PREFIX/lib64"
[ -f "$SSL_LIB/libssl.a" ] && [ -f "$SSL_LIB/libcrypto.a" ] || { echo 'Static pinned OpenSSL missing; run build-openssl-tg.sh first' >&2; exit 1; }
mkdir -p "$DEPS_DIR" "$(dirname -- "$PREFIX")"
# Do not overlay a foreign or previously compiled output. Each invocation owns
# one fresh attempt; failed source/object trees are retained for diagnosis.
[ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] || { echo 'Output prefix already exists; choose a fresh owned prefix' >&2; exit 1; }
LOCK="$PREFIX.d2ku-lock"
mkdir "$LOCK" || { echo 'Output prefix is claimed by another build' >&2; exit 1; }
trap 'rmdir "$LOCK"' EXIT HUP INT TERM
ATTEMPT=$(mktemp -d "$DEPS_DIR/attempt-$ARCH.XXXXXXXX")
FINAL_PREFIX=$PREFIX
PREFIX="$ATTEMPT/prefix"
mkdir "$PREFIX"
ARCHIVE="$DEPS_DIR/curl-$CURL_VERSION.tar.xz"
if [ ! -f "$ARCHIVE" ]; then
    curl --fail --show-error --silent --proto '=https' --proto-redir '=https' --location \
        "https://curl.se/download/curl-$CURL_VERSION.tar.xz" -o "$ARCHIVE.part"
    mv "$ARCHIVE.part" "$ARCHIVE"
fi
if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$ARCHIVE" | cut -d ' ' -f 1)
else
    actual=$(shasum -a 256 "$ARCHIVE" | cut -d ' ' -f 1)
fi
[ "$actual" = "$CURL_SHA256" ] || { echo 'libcurl source checksum mismatch' >&2; exit 1; }
# Re-extract verified bytes for each build, so stale local source edits cannot win.
SOURCE="$ATTEMPT/source"
mkdir -p "$SOURCE"
tar -xJf "$ARCHIVE" --strip-components=1 -C "$SOURCE"
TOOLS="$ATTEMPT/tools"
mkdir -p "$TOOLS"
cat > "$TOOLS/cc" <<'WRAPPER'
#!/bin/sh
# TARGET_FLAGS contains only controlled compiler flags from build-target.sh.
exec "$D2KU_ZIG" cc -target "$D2KU_TARGET" $D2KU_TARGET_FLAGS "$@"
WRAPPER
cat > "$TOOLS/ar" <<'WRAPPER'
#!/bin/sh
exec "$D2KU_ZIG" ar "$@"
WRAPPER
cat > "$TOOLS/ranlib" <<'WRAPPER'
#!/bin/sh
exec "$D2KU_ZIG" ranlib "$@"
WRAPPER
chmod 0755 "$TOOLS/cc" "$TOOLS/ar" "$TOOLS/ranlib"
OBJ="$ATTEMPT/obj"
cmake -S "$SOURCE" -B "$OBJ" -G 'Unix Makefiles' \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR="$ARCH" \
    -DCMAKE_C_COMPILER="$TOOLS/cc" -DCMAKE_AR="$TOOLS/ar" -DCMAKE_RANLIB="$TOOLS/ranlib" \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_C_FLAGS='-ffunction-sections -fdata-sections' \
    -DBUILD_CURL_EXE=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON \
    -DBUILD_TESTING=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF \
    -DHTTP_ONLY=ON -DCURL_USE_OPENSSL=ON -DOPENSSL_USE_STATIC_LIBS=ON \
    -DOPENSSL_INCLUDE_DIR="$SSL_PREFIX/include" -DOPENSSL_SSL_LIBRARY="$SSL_LIB/libssl.a" \
    -DOPENSSL_CRYPTO_LIBRARY="$SSL_LIB/libcrypto.a" \
    -DCURL_USE_PKGCONFIG=OFF -DCURL_USE_CMAKECONFIG=OFF \
    -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DUSE_NGHTTP2=OFF \
    -DUSE_LIBIDN2=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF \
    -DCURL_DISABLE_ALTSVC=ON -DCURL_DISABLE_HSTS=ON -DCURL_DISABLE_DOH=ON \
    -DCURL_DISABLE_COOKIES=ON -DCURL_DISABLE_HTTP_AUTH=ON -DCURL_DISABLE_NETRC=ON \
    -DCURL_DISABLE_MIME=ON -DCURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG=ON \
    -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none -DCURL_CA_NATIVE=OFF \
    -DENABLE_THREADED_RESOLVER=ON -DENABLE_UNIX_SOCKETS=OFF
cmake --build "$OBJ" --parallel "$JOBS"
cmake --install "$OBJ"
cat > "$ATTEMPT/smoke.c" <<'SMOKE'
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    if(curl_global_init(CURL_GLOBAL_DEFAULT)) return 1;
    const curl_version_info_data *v=curl_version_info(CURLVERSION_NOW);
    if(strcmp(v->version,"8.22.0") || !v->ssl_version || strncmp(v->ssl_version,"OpenSSL/3.5.8",13)) return 2;
    size_t count=0; for(const char *const *p=v->protocols;*p;p++) {if(strcmp(*p,"http")&&strcmp(*p,"https"))return 3;count++;}
    if(count!=2 || v->libz_version || (v->features&(CURL_VERSION_LIBZ|CURL_VERSION_BROTLI|CURL_VERSION_ZSTD|CURL_VERSION_HTTP2|CURL_VERSION_HTTP3)))return 4;
    printf("curl %s; %s; HTTP/HTTPS only; static dependency smoke OK\n",v->version,v->ssl_version);
    curl_global_cleanup();return 0;
}
SMOKE
"$TOOLS/cc" -static -Os -Wl,--gc-sections -I"$PREFIX/include" "$ATTEMPT/smoke.c" \
    "$PREFIX/lib/libcurl.a" "$SSL_LIB/libssl.a" "$SSL_LIB/libcrypto.a" -pthread -ldl -o "$ATTEMPT/smoke-$ARCH"
file "$ATTEMPT/smoke-$ARCH"
cat > "$PREFIX/PROVENANCE" <<PROVENANCE
curl_version=$CURL_VERSION
curl_commit=$CURL_COMMIT
curl_archive_sha256=$CURL_SHA256
curl_source_url=https://curl.se/download/curl-$CURL_VERSION.tar.xz
openssl_commit=$OPENSSL_COMMIT
arch=$ARCH
target=$TARGET
PROVENANCE
wc -c "$PREFIX/lib/libcurl.a" "$SSL_LIB/libssl.a" "$SSL_LIB/libcrypto.a" "$ATTEMPT/smoke-$ARCH"

# Commit only this successful attempt's output; no foreign tree is removed.
[ ! -e "$FINAL_PREFIX" ] && [ ! -L "$FINAL_PREFIX" ] || { echo 'Output appeared during build' >&2; exit 1; }
printf '%s\n' "$ATTEMPT" > "$PREFIX/BUILD_ATTEMPT"
cp "$ATTEMPT/smoke-$ARCH" "$PREFIX/curl-link-smoke"
mv "$PREFIX" "$FINAL_PREFIX"
