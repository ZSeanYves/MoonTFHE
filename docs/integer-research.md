# Integer research layer

`src/integer` provides a small radix-block API on top of the Shortint research
layer. It currently supports:

- typed signed/unsigned radix parameters;
- UInt64 encrypt/decrypt over configurable 4-bit blocks;
- homomorphic add/subtract and scalar addition with encrypted carry/borrow;
- bitwise operations, encrypted comparisons, min/max and conditional select;
- logical shifts, arithmetic signed right shift, and rotations;
- modular shift-and-add multiplication and scalar multiplication;
- unsigned restoring division/remainder with an encrypted-zero policy.

All server operations stay on ciphertexts and reuse the Shortint/Boolean PBS
path. Arithmetic is modulo `4 * block_count` bits. Division by an encrypted
zero returns quotient zero and the dividend as remainder. Signed comparison
and arithmetic right shift use two's-complement bits; signed division is
explicitly rejected until its rounding and overflow contract is fixed.

This completes the B2 CPU radix *correctness research milestone*, not mature
tfhe-rs Integer parity. The implementation still lacks packed native Shortint
encoding, cross-width casts, full signed encrypt/decrypt ergonomics, dedicated
Integer estimator fixtures, standard 8/16/32/64-bit nightly matrices,
parallelized batch PBS, and competitive performance. The `unchecked`, `smart`,
and default methods currently share the same always-refreshed Boolean path.
Those limitations remain release blockers for any production claim.
