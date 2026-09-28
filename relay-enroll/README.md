# D2K enrollment on the relay VPS

Both the router runtime and this separate VPS enrollment service are C. The
service enables public self-service installation without
shipping the fleet bootstrap credential in source, artifacts or router config.

`POST https://213.176.74.63.nip.io:9443/register` accepts exactly 120 bytes:
installation ID (16), Ed25519 public key (32), big-endian work nonce (8), and
Ed25519 signature (64). The signed message is `d2k-enroll-v1\0` followed by the
first 56 bytes. Its SHA-256 must start with 18 zero bits. Proofs bind work and
key possession to one identity; replay only repeats the same registration.

The endpoint is intentionally public enrollment, not proof of a purchased or
trusted device. It allows 6 requests per source IP/minute and 120 total/minute,
with bounded request sizes, deadlines and concurrent upstream operations. It
forwards only the fixed ID/public-key JSON to localhost `/register`, signed with
the VPS-owned bootstrap credential. Upstream credentials and responses are
never returned. Existing relay destination allowlists, session limits and
revocation still apply. The Telegram router redirect remains Telegram-only.

Build with `make` (C11 compiler and OpenSSL development libraries required).
Copy the binary, `d2k-enroll.service` and `install-server.sh` to a private temporary
directory on the existing VPS, then run `sh install-server.sh DIRECTORY` there.
This adds port 9443 and a separate service; it does not restart the shared relay.
The installer copies the bootstrap credential locally from the existing root-only
server configuration into `/etc/d2k-enroll/bootstrap.key` (0600). Systemd passes
it with `LoadCredential`. Re-run this script after a fleet secret rotation.
TLS uses the existing ACME PEM and reloads it on handshakes after renewal.

Tests: `make test`. An invalid proof must never reach the upstream;
spoofed forwarding headers must not override the real peer address. Router proof
generation is tested by `make -C ../telegram test-enroll`; the clean router install
is the end-to-end acceptance of C proof → HTTPS enrollment → relay authentication.
