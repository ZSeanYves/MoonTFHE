# 🔐 MoonTFHE: A Fully Homomorphic Encryption Library for MoonBit

[English](README.md) | [简体中文](README_zh_CN.md)

[![Build Status](https://img.shields.io/github/actions/workflow/status/ZSeanYves/MoonTFHE/moontfhe-ci.yml)](https://github.com/ZSeanYves/MoonTFHE/actions)
[![License](https://img.shields.io/github/license/ZSeanYves/MoonTFHE)](LICENSE)

**MoonTFHE** is a modular, research-oriented implementation of **Fully Homomorphic Encryption over the Torus (TFHE)** written in [**MoonBit**](https://www.moonbitlang.com/). It aims to provide the core TFHE building blocks in clear, testable MoonBit code, focusing on education, experimentation, and future extension rather than production use.

At the current stage, the project reaches up to **TRGSW external products and bootstrapping key (BSK) construction**; the full blind rotation + programmable bootstrapping + Boolean gate stack is being built step by step.

---

## 🚀 Status & Features

### Implemented so far

- Core numeric layer:
  - Torus32 representation and helpers
  - Basic modular arithmetic, rounding utilities
  - Gaussian and uniform samplers for randomness
- Encryption primitives:
  - **LWE** ciphertexts and secret keys
  - **TLWE** / **TRLWE** ring-based ciphertexts
- TFHE-specific structures:
  - **TRGSW** parameters and ciphertext type
  - Gadget decomposition for LWE → TRGSW external product
  - TRGSW ⊗ TRLWE **external product** (the main algebraic kernel for blind rotation)
  - **Bootstrapping key (BSK)** structure and generation helpers
- Bootstrap tooling:
  - LUT data structures (`Lut2`, `LutN`) and accumulator initialization helpers
  - Oracle-style (non-homomorphic) blind rotation for debugging and comparison
  - Skeleton TFHE API (`TfheParams`, programmable bootstrap helpers, gate stubs)
- Debug / test helpers:
  - Zero-noise parameter sets for tracing behaviour
  - Oracle-based XNOR gate test to validate bootstrap wiring at the logical level

### In progress / partially working

These components exist in code but are still under heavy debugging and not guaranteed correct:

- TRGSW-based **blind rotation** (`_blind_rotate_trgsw`)
- End-to-end **programmable bootstrapping (PBS)** using TRGSW + BSK
- Homomorphic Boolean gates (`tfhe_nand`, `tfhe_and`, `tfhe_or`, `tfhe_xor`, etc.) built on top of PBS

You should currently treat these pieces as **experimental** and expect failing tests, incorrect noise growth, or mismatched truth tables.

### Planned / Roadmap

The near-term roadmap is:

1. **Stabilise TRGSW blind rotation**
   - Use the already implemented TRGSW external product to drive the accumulator rotation path.
   - Match the behaviour of `_blind_rotate_trgsw` against `_blind_rotate_oracle` over a wide range of test cases (zero-noise → realistic noise).

2. **Wire TRGSW cleanly into blind rotation-based PBS**
   - Finalise programmable bootstrap using `Lut2` / `LutN` and the TRGSW-based blind rotation.
   - Make NAND/AND/OR/XOR gates pass exhaustive/random truth-table tests over encrypted bits.

3. **Noise tracking & safer parameter presets**
   - Add noise estimation helpers and “recommended” parameter profiles for different security / depth trade-offs.
   - Provide documented examples of multi-gate circuits and their noise budgets.

4. **Performance improvements**
   - Replace naive polynomial multiplication with NTT-based implementations.
   - Optimise memory layout and reduce allocations on the hot path of bootstrapping.

5. **Extended APIs**
   - Higher-level circuits and composable gate builders.
   - Better serialization for keys and ciphertexts.

MoonTFHE will remain a **research / experimentation library** even after these items land; it is not intended for production or real-world sensitive data.

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

> File names may evolve, but the overall structure looks like this.

| File                 | Module        | Description                                                     |
| -------------------- | ------------- | --------------------------------------------------------------- |
| `torus.mbt`          | `torus`       | Torus32 representation and conversion helpers.                 |
| `params.mbt`         | `params`      | TFHE parameter set (`TfheParams`, dimensions, μ, σ, etc.).     |
| `rng.mbt`            | `rng`         | Random number generator and Gaussian sampler.                  |
| `math.mbt`           | `math`        | Modular arithmetic, rounding, and numeric utilities.           |
| `noise.mbt`          | `noise`       | Noise helpers and related utilities.                           |
| `lwe.mbt`            | `lwe`         | LWE ciphertexts / keys, encrypt / decrypt.                     |
| `tlwe.mbt`           | `tlwe`        | TLWE ciphertexts and operations.                               |
| `trlwe.mbt`          | `trlwe`       | TRLWE ciphertexts (polynomial-based).                          |
| `trgsw.mbt`          | `trgsw`       | TRGSW ciphertexts, gadget decomposition, external product.     |
| `key.mbt`            | `key`         | Secret key and bootstrapping key generation.                   |
| `bsk.mbt`            | `bsk`         | Bootstrapping key structure and access helpers.                |
| `bootstrap.mbt`      | `bootstrap`   | Blind rotation, LUT-based accumulators, PBS core logic.        |
| `boostrap_exp.mbt`   | `bootstrap_exp` | Experimental / debug code for bootstrapping.                 |
| `gates.mbt`          | `gates`       | Gate stubs and debug gates (e.g. oracle XNOR test).           |
| `moon.pkg.json`      | (package)     | MoonBit package metadata.                                      |

---

## 🚀 Quick Start (WIP API Sketch)

The public API is still in flux. The following is an approximate usage pattern and may change:

```moonbit
use ZSeanYves/MoonTFHE

// 1. Choose parameters (toy values for experimentation)
let p = tfhe_params_small_trlwe() //you can also  customize by TfheParams

// 2. Generate keys (LWE, TRLWE, TRGSW/BSK)
let key_tr = trlwe_key_new(p.n_trlwe, r)

// 3. Encrypt plaintext bits
let ct = lwe_encrypt(key_lwe, bit, 3.0, r)

// 4. (Future) Evaluate a Boolean gate homomorphically
let ct2 = tfhe_id(p, bk, ct)

// 5. Decrypt the result
let dec = lwe_decrypt(key_lwe, ct2)
```

Right now this flow is **not** guaranteed to work end-to-end. Use the tests and small debug snippets in the repo to explore individual components.

---

## 🔧 Core Types (Conceptual)

Some of the key types you’ll encounter:

| Type               | Description                                                       |
| ------------------ | ----------------------------------------------------------------- |
| `Torus32`          | Fixed-point representation on the Torus (stored as `Int`).       |
| `LweCiphertext`    | Standard LWE ciphertext `{ a : Array[Int], b : Int }`.           |
| `LweKey`           | LWE secret key vector.                                           |
| `TlweCiphertext`   | TLWE ciphertext (polynomial in the torus ring).                  |
| `TrlweCiphertext`  | TRLWE ciphertext (polynomial-based, used for accumulators).      |
| `TlweKey` / `TrlweKey` | Keys for TLWE / TRLWE schemes.                              |
| `TrgswCiphertext`  | TRGSW ciphertext used to control blind rotation via external product. |
| `TrgswParams`      | Base and level parameters for TRGSW decomposition.               |
| `BootstrappingKey` | Collection of TRGSW encryptions used for LWE → TRLWE lifting.    |
| `TfheParams`       | High-level TFHE parameter bundle used across the library.        |
| `Lut2` / `LutN`    | Lookup-table encodings for programmable bootstrapping.          |

---

## ⚠️ Limitations & Disclaimer

- The library is **work in progress** and currently focuses on:
  - Prototyping blind rotation and PBS（Verified TRGSW external product and BSK construction）.
- Many pieces (especially full bootstrapping and gates) are **not yet correct**.
- Polynomial arithmetic is still naive; NTT-based optimisations are planned.
- Noise analysis and parameter choices are tuned for experiments, not security.

> **Do not use MoonTFHE for real-world sensitive data or production deployments.**

---

## 🧪 Tests

Run the included tests:

```bash
moon test -p ZSeanYves/MoonTFHE -i 10
```

Useful tests include:

- Zero-noise sanity checks for LWE / TLWE / TRLWE enc/dec.
- TRGSW gadget decomposition and external-product consistency tests.
- Oracle vs TRGSW-based blind rotation comparisons (in progress).
- Oracle XNOR truth-table tests in `gates.mbt`.

Some tests are intentionally marked as **debug / experimental** and may fail while the scheme is being developed.

---

## 📜 License

Licensed under **Apache-2.0**. See `LICENSE` for details.

---

© 2025 ZSeanYves. All rights reserved.
