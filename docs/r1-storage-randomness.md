# R1 continuous storage and exact noise

R1 replaces the reference core's nested ciphertext storage with canonical,
contiguous `FixedArray[UInt]` buffers. The layouts are:

- LWE ciphertext: `mask || body`.
- GLWE ciphertext: `(k + 1) * N`, with `k` masks followed by the body.
- GGSW ciphertext: `level * (k + 1) * (k + 1) * N`.
- Key switching key: `input_dimension * level * (output_dimension + 1)`.

Core constructors validate the complete expected length before accepting a flat
buffer. Public copy accessors are intended for serialization, fixtures, and the
native ABI; they do not expose mutable aliases to owned key material.

`KeyId` is now a non-secret 128-bit value. MBCT v2, MBKS v1, and MTSK v1 carry
all 16 bytes. Test key generation uses a deterministic namespace and seed;
production key generation must fill both words from the key-generation CSPRNG.

Client encryption owns separate ChaCha20 streams for the LWE mask and noise.
Production entropy failures remain explicit and never fall back to test seeds.

## Discrete Gaussian fixtures

Standard Boolean Gaussian sampling uses a complete 128-bit absolute-value CDT.
There is one threshold for every magnitude from zero through the eight-sigma
tail bound. Thresholds are split into generated chunks of at most 4096 entries.
Each chunk is a compiler-friendly hexadecimal payload decoded once into
`(high, low)` unsigned 64-bit words when the fixture is constructed. No
magnitude subsampling or floating-point arithmetic occurs in the runtime
sampler.

The canonical metadata is in
`tools/noise_fixtures/standard-cdt.json`. It records the Q32 sigma, tail bound,
entry count, generator version, threshold width, and SHA-256 of the little-endian
128-bit threshold stream. Estimator inputs reference these exact hashes and
remain `reference_only` until the locked estimator is executed in R6.

These fixtures establish reproducible implementation semantics. They do not by
themselves establish a security level, side-channel resistance, or production
readiness.
