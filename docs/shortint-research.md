# Shortint research layer

`src/shortint` is the first CPU API layer above Boolean Core. It is intentionally
small and explicit about its current boundary:

- a short integer is represented as little-endian Boolean ciphertext blocks;
- `message_modulus` and `carry_modulus` are validated power-of-two metadata;
- `encrypt`, `decrypt`, and ripple-carry `add` reuse the existing Boolean PBS;
- `Degree` and `NoiseLevel` are tracked as typed metadata for API experiments.

This is not yet the tfhe-rs Shortint encoding. It does not provide native
message/carry packing, smart/default carry propagation, shortint parameter
security estimates, or the Shortint operation matrix. The layer exists to
validate typed API ownership and arithmetic orchestration without creating a
second cryptographic implementation. Standard Shortint claims remain blocked
until the estimator, noise model, and packed PBS representation are added.
