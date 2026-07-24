# MoonTFHE

[简体中文](README_zh.md)

[![MoonTFHE CI](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml/badge.svg)](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml)

MoonTFHE is a research implementation of TFHE building blocks in MoonBit. The
repository is being rebuilt from an unmaintained teaching prototype into a
testable library with explicit client/server key boundaries.

> Security status: **not suitable for production or sensitive data**. The
> current key generation and encryption path uses deterministic SplitMix64 and
> a CLT noise approximation. Standard security parameters and a secret-free
> server key are not available yet.

## Current status

The maintained baseline includes Torus32 arithmetic, naive negacyclic
polynomials, LWE/TLWE/TRLWE encryption, signed high-bit key switching, TRGSW
external products, sample extraction, a secret-free encrypted BSK, real TRGSW
blind rotation, PBS->KS, and experimental unary/NAND/AND/OR gates.

The following remain explicitly experimental or incomplete:

- production-grade parameter sets and a complete security estimate;
- a secure-randomness client-key facade on every backend;
- ciphertext serialization and version validation;
- any claim of 110-bit or 128-bit security;
- resistance to side-channel attacks.

The old oracle now lives only in `oracle_wbtest.mbt`. It receives a test secret
explicitly and exists solely as a reference. `BootstrappingKey` contains only
encrypted GGSW data, dimensions, and an encrypted key-switching key; it is the
evaluation object used by the current PBS path, but it is not yet a hardened
production server key.

## Build and test

Install a current MoonBit toolchain, then run:

```bash
moon check --target all --warn-list +73
moon test --target native
moon info --target all
moon fmt --check
```

CI runs the test suite on `wasm`, `wasm-gc`, `js`, and `native`.

## Experimental example

This example is deterministic and intentionally named `experimental_*` so it
cannot be confused with a secure production path.

```mbt check
test {
  let client = experimental_keygen(64, 3.0, 0x4D4F4F4E)
  let encrypted = client.encrypt(true)
  let encrypted_not = encrypted.not()
  assert_eq(client.decrypt(encrypted_not), false)
}
```

## Roadmap

The breaking P0-P6 migration is tracked in
[`docs/maintenance-roadmap.md`](docs/maintenance-roadmap.md). Test ownership and
the role of reference/oracle checks are documented in
[`docs/testing.md`](docs/testing.md).

The target architecture follows the separation used by mature TFHE libraries:
a private client key, a server key containing only evaluation material, opaque
Boolean ciphertexts, validated parameters, secure entropy and sampling, real
blind rotation, and independently verified test fixtures.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
