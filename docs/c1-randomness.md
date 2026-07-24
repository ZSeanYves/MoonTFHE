# C1 randomness contract

The maintained `src/random` package now has one production entropy boundary:

- native reads OS entropy through the C stub;
- JavaScript uses `globalThis.crypto.getRandomValues`;
- wasm and wasm-gc require an installed `EntropyProvider`;
- provider failures and short buffers are returned as structured errors.

`RandomDomain` labels derive independent ChaCha20 streams for key generation,
encryption masks/noise, bootstrap keys, and serialization nonces. The stream
core is the RFC 8439 20-round construction; the RFC block vector is tested on
all four targets.

The fixed-point CDT fixture in `tools/noise_fixtures` is the only maintained
Gaussian sampler. It stores a Q32.32 sigma identifier, an explicit tail bound,
and a SHA-256 fixture hash. The sigma=3 table is intentionally a C1 toy fixture;
standard 110/128-bit tables remain reference-only until the C3 estimator and
PBS implementation are connected.

The old floating-point sampler remains only in the deprecated root
compatibility implementation. It is excluded from the maintained production
packages and is not used by the new GLWE path.
