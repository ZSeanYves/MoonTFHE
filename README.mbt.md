# MoonTFHE

[简体中文](README_zh.md)

[![MoonTFHE CI](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml/badge.svg)](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml)

MoonTFHE is a research implementation of TFHE building blocks in MoonBit. The
repository is being rebuilt from an unmaintained teaching prototype into a
testable library with explicit client/server key boundaries.

> Security status: **research release; not suitable for production or
> sensitive data**. Standard 110/128-bit key generation and Fourier PBS remain
> gated behind the remaining RC phases.

## Current status

The maintained baseline includes Torus32 arithmetic, typed LWE/GLWE/GGSW
entities, signed key switching, sample extraction, a secret-free typed BSK,
reference blind rotation, PBS->KS, and Boolean NAND/NOT/AND/OR/XOR/XNOR/MUX
through the stable facade.

The following remain explicitly experimental or incomplete:

- production-grade standard parameter key generation and a complete security
  estimate;
- Fourier-domain BSK/PBS and native performance parity;
- any claim of 110-bit or 128-bit security;
- resistance to side-channel attacks.

The maintained `src/boolean` facade exposes opaque `ClientKey`, `ServerKey`,
and `Ciphertext` types, versioned `MBCT` ciphertext envelopes, and the Boolean
gate surface. Production `generate_keys` deliberately returns
`UnsupportedBackend` until secure key generation is fully connected.

The old root package and `MTFH`/`MBCT v1` formats were removed in C7.
`BootstrappingKey` contains only encrypted GGSW data, dimensions, and an
encrypted key-switching key; it is the typed evaluation object used by the
current reference PBS path. `MBCT v2` is the only ciphertext format currently
written; formal ServerKey/ClientKey import is delivered in C12.

## Build and test

Install a current MoonBit toolchain, then run:

```bash
moon check --target all --warn-list +73
moon test --target native
moon info --target all
moon fmt --check
```

CI runs the test suite on `wasm`, `wasm-gc`, `js`, and `native`.

## Boolean reference example

The deterministic constructor is explicitly test-only. It exercises the typed
reference backend and is not a production key-generation API:

```mbt check
test {
  let (client, server) = generate_test_keys(boolean_test_parameters(), 0x50464F).unwrap()
  let result = server.nand(client.encrypt(true), client.encrypt(false)).unwrap()
  assert_eq(client.decrypt(result).unwrap(), true)
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
