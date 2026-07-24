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
polynomials, LWE/TLWE/TRLWE encryption, legacy key switching, TRGSW external
products, sample extraction, and a deterministic experimental LWE facade.

The following are deliberately absent from the stable public API:

- programmable bootstrapping and Boolean NAND/AND/OR;
- the plaintext oracle used by legacy bootstrap tests;
- any claim of 110-bit or 128-bit security;
- cryptographically secure key generation.

The old oracle now lives only in `oracle_wbtest.mbt`. It can inspect legacy
secret fields and exists solely as a test reference. The current
`BootstrappingKey` representation still embeds those fields and will be replaced
in P3; do not serialize or distribute it as a server key.

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
