# O6 portable semantics

JS, wasm and wasm-gc share the native Torus32 encoding, signed decomposition,
packed layout and serialization fixtures. Their PBS implementation remains the
coefficient `O(N^2)` reference backend and carries no latency commitment.

Every PR runs toy truth tables, entropy-failure contracts and the same packed
ciphertext snapshot on all four targets. The scheduled evidence workflow also
runs a 110-bit JS keygen/NAND smoke with an explicitly installed host entropy
adapter. Portable standard construction never falls back to a time seed or an
implicit deterministic provider; a missing wasm host adapter returns
`UnsupportedBackend`.
