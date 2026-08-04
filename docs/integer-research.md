# Integer research layer

`src/integer` provides a small radix-block API on top of the Shortint research
layer. It currently supports:

- typed signed/unsigned radix parameters;
- UInt64 encrypt/decrypt over configurable 4-bit blocks;
- homomorphic radix addition with an explicit encrypted carry path.

The implementation is an orchestration and ownership test, not a mature
tfhe-rs Integer implementation. It does not yet provide smart/default carry
semantics, multiplication, division/remainder, comparisons, shifts, signed
overflow rules, compact/public-key encryption, or Integer-specific security
estimates. Those features remain blocked on packed Shortint encoding,
noise-aware metadata, and a dedicated estimator fixture set.
