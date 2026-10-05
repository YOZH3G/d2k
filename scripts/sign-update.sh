#!/bin/sh
# Trusted release-host tool; key path must come from an externally protected environment.
# No trace, key generation, publishing, or router installation.
set -eu
[ "$#" -eq 2 ] || { echo 'usage: sign-update.sh DOCUMENT SIGNATURE' >&2; exit 2; }
: "${D2K_SIGNING_KEY:?external Ed25519 private key path required}"
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
python3 - "$ROOT/scripts" "$1" "$2" <<'PY'
import os, sys
sys.path.insert(0,sys.argv[1])
from update_release_provenance import atomic, regular, sign
atomic(sys.argv[3],sign(regular(sys.argv[2],1048576),os.environ['D2K_SIGNING_KEY']))
PY
