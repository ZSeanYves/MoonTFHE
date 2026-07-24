# Test Inventory

The P0 baseline classifies tests by purpose. Every retained test has an
observable assertion; historical print-only probes were removed.

## Contract tests

- `torus.mbt`: wrapping arithmetic, Boolean encoding, fixed-point conversion.
- `math.mbt`: deterministic RNG behavior, coarse sampler statistics,
  negacyclic polynomial arithmetic, and legacy decomposition behavior.
- `lwe.mbt`, `tlwe.mbt`, `trlwe.mbt`: encryption/decryption and noise bounds.
- `key.mbt`: legacy LWE key-switch round trips.
- `trgsw.mbt`: legacy external-product behavior.
- `bootstrap.mbt`: sample extraction at constant and nonzero coefficients.

## Regression tests

- `bsk.mbt`: bootstrapping-key shape and encrypted control-bit behavior.
- Tests with fixed seeds pin behavior while the P2/P3 implementation is
  replaced. They are not cryptographic test vectors and do not prove security.

## Reference tests

- `oracle_wbtest.mbt` is a white-box-only plaintext oracle for ID, NOT, XNOR,
  and XOR. It deliberately reads legacy secret fields and is excluded from the
  generated package interface.

## Black-box tests

- `experimental_api_test.mbt` uses only public symbols and exercises
  key generation -> encryption -> homomorphic NOT -> decryption.
- `boolean_api_test.mbt` uses only the public Boolean facade and exercises
  NAND, the complete Boolean gate truth tables, cross-key rejection, versioned
  ciphertext round trips, checksum rejection, and the explicit unsupported LUT
  contract.

## Current B6 serialization contract

`src/boolean` ciphertexts use an `MBCT` envelope containing a format version,
parameter code, LWE dimension, key tag, payload length, and an FNV-style
checksum. The checksum detects accidental corruption; it is not an
authenticated encryption scheme. Client and server key serialization remains
intentionally unavailable until a secret-safe format and audit are completed.

The P1 suite replaces self-referential legacy checks with independent
reference arithmetic, boundary cases, pinned fixtures, and circuit properties.
