# C5 serialization boundary

The Boolean facade writes only `MBCT` version 2 ciphertexts. The format records
the format kind, parameter code, dimension, key identity, Torus32 modulus marker,
decomposition marker, distribution marker, payload length, and a Castagnoli
CRC32C. Version 1 `MBCT` and `MTFH` values are rejected after the C7 breaking
migration.

The parser checks every length and metadata field before passing the payload to
the opaque ciphertext decoder. A changed payload returns `ChecksumMismatch`;
cross-key and cross-parameter values return `ParameterMismatch`.

`SerializationKey` accepts exactly 32 bytes. `ClientKey::export_secret` builds
an authenticated `MTSK` envelope with a fresh entropy-backed nonce and delegates
AES-256-GCM to the native provider; portable backends return
`UnsupportedBackend` unless a trusted provider is available.
`ClientKey::import_secret` authenticates and restores MTSK on native; wrong
keys and tags return `AuthenticationFailed`. MBKS currently carries only a
secret-free structural marker, not the complete GGSW/KSK payload, so
`ServerKey::deserialize` remains a release blocker.
