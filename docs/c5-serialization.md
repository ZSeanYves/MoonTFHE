# C5 serialization boundary

The Boolean facade now writes `MBCT` version 2 ciphertexts. The format records
the format kind, parameter code, dimension, key identity, Torus32 modulus marker,
decomposition marker, distribution marker, payload length, and a Castagnoli
CRC32C. Version 1 `MBCT` values are accepted read-only and continue to use the
legacy checksum so existing fixtures can be migrated without rewriting them.

The parser checks every length and metadata field before passing the payload to
the opaque ciphertext decoder. A changed payload returns `ChecksumMismatch`;
cross-key and cross-parameter values return `ParameterMismatch`.

`SerializationKey` accepts exactly 32 bytes. `ClientKey::export_secret` builds
an authenticated `MTSK` envelope with a fresh entropy-backed nonce and delegates
AES-256-GCM to the native provider; portable backends return
`UnsupportedBackend` unless a trusted provider is available. `ServerKey`
serializes the encrypted GGSW/KSK payload in `MBKS` with CRC32C. The client
secret is never emitted as plaintext and the server payload traversal does not
read secret fields. Import/deserialization of key envelopes remains a release
blocker.
