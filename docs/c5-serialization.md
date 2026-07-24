# C5 serialization boundary

The Boolean facade now writes `MBCT` version 2 ciphertexts. The format records
the format kind, parameter code, dimension, key identity, Torus32 modulus marker,
decomposition marker, distribution marker, payload length, and a Castagnoli
CRC32C. Version 1 `MBCT` values are accepted read-only and continue to use the
legacy checksum so existing fixtures can be migrated without rewriting them.

The parser checks every length and metadata field before passing the payload to
the opaque ciphertext decoder. A changed payload returns `ChecksumMismatch`;
cross-key and cross-parameter values return `ParameterMismatch`.

`SerializationKey` accepts exactly 32 bytes. `ClientKey::export_secret` and
`ServerKey::serialize` are intentionally present as explicit API boundaries but
return `UnsupportedBackend` until the core exposes the complete secret payload
and encrypted BSK/KSK payload respectively. No metadata-only server key or
partial client secret is emitted. The Rust AES-256-GCM provider in C4 is tested
through its stable C ABI; wiring it to the opaque MoonBit key representation is
the remaining C5 integration work.
