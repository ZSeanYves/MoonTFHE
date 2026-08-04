# MoonTFHE

[简体中文](README_zh.md)

[![MoonTFHE CI](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml/badge.svg)](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml)

MoonTFHE is a research implementation of TFHE building blocks in MoonBit. The
repository is being rebuilt from an unmaintained teaching prototype into a
testable library with explicit client/server key boundaries.

> Security status: **research release; not suitable for production or
> sensitive data**. The Boolean Core correctness and CI gates pass, but the
> performance gate and independent cryptographic/side-channel audits are not
> complete.

## Current status

The maintained baseline includes Torus32 arithmetic, typed LWE/GLWE/GGSW
entities, signed key switching, sample extraction, a secret-free typed BSK,
reference blind rotation, PBS->KS, and Boolean NAND/NOT/AND/OR/XOR/XNOR/MUX
through the stable facade.

The following limits remain:

- the estimator's GLWE result is a documented flattened-LWE approximation;
- portable standard execution uses the correct reference backend without a
  performance commitment;
- no externally audited 110-bit or 128-bit security claim is made;
- resistance to side-channel attacks.

The maintained `src/boolean` facade exposes opaque `ClientKey`, `ServerKey`,
and `Ciphertext` types, versioned `MBCT` ciphertext envelopes, complete `MBKS`
server-key import/export, authenticated `MTSK` secret import/export, and the
Boolean gate surface. Production `generate_keys` supports the native 110/128-bit
parameter records. Portable standard construction requires trusted host entropy.

The old root package and `MTFH`/`MBCT v1` formats were removed in C7.
`BootstrappingKey` contains only encrypted GGSW data, dimensions, and an
encrypted key-switching key. Native evaluation uses a reusable Fourier context;
portable targets retain the coefficient reference path. `MBCT v3`, `MBKS v2`
and authenticated `MTSK v2` are the only supported formats, with complete
Ciphertext, ServerKey and explicit ClientKey import/export.

The latest same-runner evidence records worst-case PBS/NAND ratios of about
4.2x against the pinned tfhe-rs Boolean harness, zero steady-state native PBS
heap allocations, and passing 1,000-step chained circuits for both sets. The
division-free native rotation optimization is measured and differential-tested,
but the required 2x performance target is not met.

This repository is versioned as `0.2.0-research`. It is not an RC or a
production security release.

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
