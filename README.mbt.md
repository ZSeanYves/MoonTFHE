# 🔐 MoonTFHE: A Fully Homomorphic Encryption Library for MoonBit

[English](https://github.com/ZSeanYves/MoonTFHE/blob/main/README.md) | [简体中文](https://github.com/ZSeanYves/MoonTFHE/blob/main/README_zh_CN.md)

[![Build Status](https://img.shields.io/github/actions/workflow/status/ZSeanYves/MoonTFHE/moontfhe-ci.yml)](https://github.com/ZSeanYves/MoonTFHE/actions)
[![License](https://img.shields.io/github/license/ZSeanYves/MoonTFHE)](LICENSE)

**MoonTFHE** is a modular, research-oriented implementation of **Fully Homomorphic Encryption over the Torus (TFHE)** written in [**MoonBit**](https://www.moonbitlang.com/). It implements the essential components of the TFHE scheme, including **LWE**, **TLWE**, **TRLWE**, **TRGSW**, **bootstrapping**, and **programmable bootstrapping**, with a strong focus on readability, testability, and modularity.

---

## 🚀 Features

* Complete low-level primitives: **Torus**, **LWE**, **TLWE**, **TRLWE**, **TRGSW**
* Supports **bootstrapping** and **programmable bootstrapping (PBS)**
* Boolean gates: **NAND**, **AND**, **OR**, **XOR** over encrypted bits
* Configurable parameters (`n`, `N`, `σ`) for experimentation
* Gaussian and uniform samplers for secure randomness
* Modular design: each encryption layer in its own file
* Clear test coverage for encryption correctness and gate logic

---

## 📦 Installation

```bash
moon add ZSeanYves/MoonTFHE
```

Or edit `moon.mod.json`:

```json
"import": ["ZSeanYves/MoonTFHE"]
```

---

## 🧩 Module Overview

| File            | Module      | Description                                            |
| --------------- | ----------- | ------------------------------------------------------ |
| `torus.mbt`     | `torus`     | Defines Torus32 representation and conversion helpers. |
| `params.mbt`    | `params`    | Encryption parameters (n, N, σ, μ).                    |
| `rng.mbt`       | `rng`       | Random number generator and Gaussian sampler.          |
| `math.mbt`      | `math`      | Modular arithmetic, rounding, and numeric utilities.   |
| `lwe.mbt`       | `lwe`       | LWE ciphertexts, encryption/decryption.                |
| `tlwe.mbt`      | `tlwe`      | TLWE ring-based ciphertexts.                           |
| `trlwe.mbt`     | `trlwe`     | TRLWE ciphertexts (polynomial-based).                  |
| `trgsw.mbt`     | `trgsw`     | TRGSW ciphertexts used in bootstrapping.               |
| `key.mbt`       | `key`       | Secret key and bootstrap key generation.               |
| `bsk.mbt`       | `bsk`       | Bootstrapping key structure and serialization.         |
| `bootstrap.mbt` | `bootstrap` | Bootstrapping and programmable bootstrapping routines. |
| `gates.mbt`     | `gates`     | Boolean logic gates built on top of PBS.               |

---

## 🚀 Quick Start

### Encrypt, Evaluate, Decrypt

```moonbit
use ZSeanYves/MoonTFHE

let params = gen_default_params()
let (sk_lwe, sk_trlwe, bsk) = gen_keys(params, seed = 2025)

let ct_x = lwe_encrypt_bit(sk_lwe, true)
let ct_y = lwe_encrypt_bit(sk_lwe, false)

let ct_out = nand(params, ct_x, ct_y, bsk)
let res = lwe_decrypt_bit(sk_lwe, ct_out)

assert(res == true)
```

### Programmable Bootstrapping Example

```moonbit
let lut = make_bool_lut(|x| { !x }) // Boolean NOT LUT
let ct_z = programmable_bootstrap(params, ct_x, lut, bsk)
let z = lwe_decrypt_bit(sk_lwe, ct_z)
```

---

## 🔧 API Reference

### 🏗 Core Types

| Type                 | Description                               |
| -------------------- | ----------------------------------------- |
| `Torus32`            | Fixed-point representation on the Torus.  |
| `LweCt` / `LweSk`    | LWE ciphertext and secret key.            |
| `TlweCt` / `TrlweCt` | TLWE/TRLWE ciphertexts for bootstrapping. |
| `TrgswCt`            | TRGSW ciphertexts used in blind rotation. |
| `BootstrapKey`       | Key enabling LWE→TRLWE conversion.        |

### 📤 Core Functions

| Function                      | Signature                                              | Description                          |
| ----------------------------- | ------------------------------------------------------ | ------------------------------------ |
| `gen_default_params`          | `() -> Params`                                         | Returns recommended parameter set.   |
| `gen_keys`                    | `(Params, seed:Int) -> (LweSk, TrlweSk, BootstrapKey)` | Generates secret and bootstrap keys. |
| `lwe_encrypt_bit`             | `(LweSk, Bool) -> LweCt`                               | Encrypts a single bit.               |
| `lwe_decrypt_bit`             | `(LweSk, LweCt) -> Bool`                               | Decrypts ciphertext to Boolean.      |
| `bootstrap`                   | `(Params, LweCt, BootstrapKey) -> LweCt`               | Standard bootstrapping.              |
| `programmable_bootstrap`      | `(Params, LweCt, Lut, BootstrapKey) -> LweCt`          | Bootstrapping with LUT mapping.      |
| `nand` / `and` / `or` / `xor` | `(Params, LweCt, LweCt, BootstrapKey) -> LweCt`        | Boolean gates built via PBS.         |

---

## ⚠️ Error Types

`TfheError` (a `suberror` enum) may be raised during encryption or bootstrapping:

| Variant             | Description                          |
| ------------------- | ------------------------------------ |
| `InvalidParams`     | Invalid or mismatched parameter set. |
| `NoiseOverflow`     | Decryption noise exceeded limit.     |
| `KeyMismatch`       | Secret/Bootstrap key mismatch.       |
| `LutOutOfRange`     | PBS lookup table value out of range. |
| `NotImplementedYet` | Placeholder for future functions.    |

---

## 🧭 Common Patterns

```moonbit
// Boolean Gate Composition
let a = lwe_encrypt_bit(sk_lwe, true)
let b = lwe_encrypt_bit(sk_lwe, true)
let c = xor(params, a, b, bsk)
let result = lwe_decrypt_bit(sk_lwe, c)
assert(result == false)

// Chained Bootstrapping
let refreshed = bootstrap(params, c, bsk)
let recovered = lwe_decrypt_bit(sk_lwe, refreshed)
```

---

## ❗ Limitations

* Currently focused on Boolean gates and small parameter sets.
* Polynomial multiplication is naive (NTT acceleration in progress).
* Noise estimation and ciphertext modulus switching are experimental.
* Not yet security-audited; research use only.

---

## 🧪 Tests

Run included test suites:

```bash
moon test -p ZSeanYves/MoonTFHE -i 10
```

Tests cover:

* Boolean gate truth tables (NAND, AND, OR, XOR)
* Bootstrapping round-trip correctness
* Gaussian sampling distribution validation
* Randomized property-based checks

---

## 📜 License

Licensed under **Apache-2.0**. See [LICENSE](LICENSE) for details.

---

© 2025 ZSeanYves. All rights reserved.
