# Test fixtures only

`index-v1.json` and `manifest-v1.json` show exact unsigned schema=1 bytes used by
`test_manifest.c` (no trailing newline). Their repeated `a` hashes are metadata
examples, not payload-validation evidence. The test signs originals and mutations
in-process with OpenSSL EVP. Deterministic seeds are 32 bytes of `07` and, for the
rotation test, 32 bytes of `08`. They are public test material, never release keys.
No production private key, signed release or bootstrap trust is provided here.
