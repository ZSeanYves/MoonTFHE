# O5 serialization boundary

The Boolean facade writes only `MBCT` version 3 ciphertexts. Its integrity
metadata records the parameter code, LWE/GLWE dimensions, polynomial size,
PBS/KSK decomposition, full 128-bit key identity, Torus32 modulus marker,
distribution marker, packed-layout identifier, payload length, and a Castagnoli
CRC32C. Earlier `MBCT` and `MTFH` values return `UnsupportedVersion`; no
compatibility parser or automatic migration remains.

The parser checks every length and metadata field before passing the payload to
the opaque ciphertext decoder. A changed payload returns `ChecksumMismatch`;
cross-key and cross-parameter values return `ParameterMismatch`.

`SerializationKey` accepts exactly 32 bytes. `ClientKey::export_secret` builds
an authenticated `MTSK v2` envelope with a fresh entropy-backed nonce. Its AAD
contains the complete parameter structure, full KeyId, and payload length before
delegating AES-256-GCM to the native provider. `ClientKey::import_secret`
authenticates and restores MTSK; wrong keys and tags return
`AuthenticationFailed`.

`MBKS v2` stores the complete contiguous coefficient BSK followed by the KSK.
It never stores the client LWE/GLWE secret or the native Fourier cache. Import
checks the exact parameter-derived shape, bounded length and CRC before any key
allocation, reconstructs typed KSK/GGSW state, then rebuilds the Fourier cache
on native. Portable targets retain the same coefficient representation and use
the reference PBS backend. `MBKS v1` and `MTSK v1` return
`UnsupportedVersion` before payload allocation or authentication work.
