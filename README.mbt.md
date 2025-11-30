# MoonTFHE README (English)

[English](#moontfhe-readme-english) | [简体中文](#moontfhe-自述文件-中文)

---

# 🔐 MoonTFHE: A Fully Homomorphic Encryption Library for MoonBit

[![Build Status](https://img.shields.io/github/actions/workflow/status/ZSeanYves/MoonTFHE/moontfhe-ci.yml)](https://github.com/ZSeanYves/MoonTFHE/actions)
[![License](https://img.shields.io/github/license/ZSeanYves/MoonTFHE)](LICENSE)

**MoonTFHE** is a modular, research-oriented implementation of **Fully Homomorphic Encryption over the Torus (TFHE)** written in MoonBit.
The goal is to expose the **core TFHE building blocks** (LWE / TLWE / TRLWE / TRGSW, key-switching, bootstrapping key, programmable bootstrapping) in **clear, testable MoonBit code**, so that you can read, hack and experiment rather than treat the scheme as a black box.

At the current stage the implementation reaches **TRGSW external products and bootstrapping-key (BSK) construction**; TRGSW-driven blind rotation and full programmable bootstrapping are still under active development.

> ⚠️ This is an **experimental research library** – not for production or real-world sensitive data.

---

## 🚦 Status & Features

### Implemented

* **Numeric / Torus layer**

  * Torus32 fixed-point representation and helpers (`T32_HALF`, `T32_QUARTER`, add/sub helpers).
  * Modular arithmetic and rounding utilities.

* **Randomness & noise**

  * Lightweight reproducible PRNG `CsPrng` (SplitMix64).
  * Discrete Gaussian noise samplers for LWE / TRLWE.

* **Basic encryption schemes**

  * **LWE**: `LweKey`, `LweCiphertext`, internal `lwe_encrypt` / `lwe_decrypt`.
  * **TLWE**: `TlweKey`, `TlweCiphertext` over a ring.
  * **TRLWE**: `TrlweKey`, `TrlweCiphertext` for ring-based ciphertexts and accumulators.

* **TFHE-specific structures**

  * `TfheParams` as a single bundle of TFHE parameters.
  * **TRGSW**:

    * `TrgswParams`, `TrgswCiphertext`.
    * Gadget decomposition and TRGSW ⊗ TRLWE **external product** (algebraic core of blind rotation).
  * **Key switching**:

    * `KskParams`, `KeySwitchKey`.
    * `ksk_generate`, `ksk_apply`.
  * **Bootstrapping key (BSK)**:

    * `BskParams`, `BootstrappingKey`.
    * `bsk_generate` builds a BSK from an LWE key and a TRLWE key.

* **Programmable bootstrapping & gates (API skeleton)**

  * Lookup tables: `Lut2`, `LutN`.
  * Single-bit programmable bootstrap:

    * `programmable_bootstrap(p, bk, ct, f_true, f_false)`.
    * Convenience wrappers `tfhe_id`, `tfhe_not`.
  * Binary programmable bootstrap:

    * `programmable_bootstrap_bin(p, bk, ct, lut)`.
  * Boolean gates built on top of PBS:

    * `tfhe_xnor`, `tfhe_xor`, `tfhe_nand`, `tfhe_and`, `tfhe_or`.

* **Debugging helpers**

  * Zero-noise parameter presets for tracing exact behaviour.
  * Oracle-style blind rotation and PBS (non-homomorphic, uses secret key) for reference.
  * Tests comparing TRGSW external product against oracle behaviour.

### In progress / experimental

These pieces exist in code but should be treated as **experimental**:

* TRGSW-driven blind rotation (`_blind_rotate_trgsw`).
* Full programmable bootstrapping pipeline using TRGSW + BSK.
* Homomorphic Boolean gates `tfhe_*` running on the TRGSW path instead of the oracle path.
* Noise tracking and safer parameter presets.

The current PBS path still calls an **oracle blind rotation** internally for most tests, so it is **not yet a fully homomorphic implementation** end-to-end.

---

## 📦 Installation

```bash
moon add ZSeanYves/MoonTFHE
```

or add to `moon.mod.json`:

```json
{
  "import": ["ZSeanYves/MoonTFHE"]
}
```

---

## 🧩 Module Layout

> File names may evolve, but the high-level structure looks like this.

| File               | Module          | Description                                                      |
| ------------------ | --------------- | ---------------------------------------------------------------- |
| `torus.mbt`        | `torus`         | Torus32 representation, constants, add/sub, encode/decode.       |
| `params.mbt`       | `params`        | `TfheParams` presets and helpers.                                |
| `rng.mbt`          | `rng`           | `CsPrng` PRNG and random helpers.                                |
| `math.mbt`         | `math`          | Modular arithmetic and numeric utilities.                        |
| `noise.mbt`        | `noise`         | Noise sampling helpers.                                          |
| `lwe.mbt`          | `lwe`           | `LweKey`, `LweCiphertext`, enc/dec and phase helpers.            |
| `tlwe.mbt`         | `tlwe`          | `TlweKey`, `TlweCiphertext`, ring-based enc/dec.                 |
| `trlwe.mbt`        | `trlwe`         | `TrlweKey`, `TrlweCiphertext`, polynomial enc/dec.               |
| `trgsw.mbt`        | `trgsw`         | `TrgswParams`, `TrgswCiphertext`, external products.             |
| `key.mbt`          | `key`           | Key-switching parameters and keys (`KskParams`, `KeySwitchKey`). |
| `bsk.mbt`          | `bsk`           | `BskParams`, `BootstrappingKey`, BSK generation.                 |
| `bootstrap.mbt`    | `bootstrap`     | LUTs, programmable bootstrap, Boolean gates.                     |
| `boostrap_exp.mbt` | `bootstrap_exp` | Experimental / debug code for PBS.                               |
| `gates.mbt`        | `gates`         | Additional gate tests and oracle wiring.                         |
| `moon.pkg.json`    | —               | MoonBit package metadata.                                        |

---

## 🔧 Core Data Types

A small subset of the most important structures:

| Type               | Where       | Description                                                    |
| ------------------ | ----------- | -------------------------------------------------------------- |
| `TfheParams`       | `params`    | Bundle of all TFHE parameters (LWE dims, TRLWE dims, bases…).  |
| `CsPrng`           | `rng`       | Simple reproducible PRNG used everywhere.                      |
| `LweKey`           | `lwe`       | Binary LWE secret key `s ∈ {0,1}^n`.                           |
| `LweCiphertext`    | `lwe`       | LWE ciphertext `{ a : Array[Int], b : Int }`.                  |
| `TlweKey`          | `tlwe`      | TLWE secret key (ring binary polynomial).                      |
| `TlweCiphertext`   | `tlwe`      | TLWE ciphertext over `T[X]/(X^n+1)`.                           |
| `TrlweKey`         | `trlwe`     | TRLWE secret key for ring-based ciphertexts.                   |
| `TrlweCiphertext`  | `trlwe`     | TRLWE ciphertext used for accumulators in blind rotation.      |
| `TrgswParams`      | `trgsw`     | TRGSW base / level / ring dimension.                           |
| `TrgswCiphertext`  | `trgsw`     | TRGSW ciphertext encoding a control bit for external products. |
| `KskParams`        | `key`       | Key-switching parameters `(base_log, level)`.                  |
| `KeySwitchKey`     | `key`       | LWE → LWE key-switching key.                                   |
| `BskParams`        | `bsk`       | Bootstrapping key parameters `(base_log, level)`.              |
| `BootstrappingKey` | `bsk`       | LWE → TRLWE bootstrapping key.                                 |
| `Lut2`             | `bootstrap` | Two-entry LUT (for single-bit PBS: `f(0), f(1)`).              |
| `LutN`             | `bootstrap` | General LUT over `n_trlwe` entries.                            |

These types are designed to mirror the original TFHE papers as closely as possible, while remaining idiomatic in MoonBit.

---

## 🔌 Public API Overview

Below is a **practical view of the main entry points** you’ll most often interact with. Some helpers are still internal and currently only used by tests; the plan is to gradually promote them to a stable public API as the implementation stabilises.

### 1. Parameter presets

Module: `ZSeanYves/MoonTFHE/params`

```moonbit
pub struct TfheParams { ... }

pub fn tfhe_params_small_trlwe() -> TfheParams
pub fn tfhe_params_tiny_trlwe()  -> TfheParams
```

* `tfhe_params_small_trlwe()` – “small but complete” parameter set for experiments.
* `tfhe_params_tiny_trlwe()` – even smaller toy parameters for debugging.

### 2. Key switching

Module: `ZSeanYves/MoonTFHE/key`

```moonbit
pub struct KskParams {
  base_log : Int
  level    : Int
}

pub struct KeySwitchKey {
  params : KskParams
  n_in   : Int
  n_out  : Int
  data   : Array[LweCiphertext]
}

pub fn ksk_generate(
  p0      : TfheParams,
  key_in  : LweKey,
  key_out : LweKey,
  rng     : CsPrng,
) -> KeySwitchKey

pub fn ksk_apply(
  p0    : TfheParams,
  ksk   : KeySwitchKey,
  ct_in : LweCiphertext,
) -> LweCiphertext
```

* `ksk_generate` builds a key-switching key from an **input** and **output** LWE key.
* `ksk_apply` transforms a ciphertext under `key_in` into one under `key_out`, preserving the underlying plaintext bit (within noise tolerance).

### 3. Bootstrapping key

Module: `ZSeanYves/MoonTFHE/bsk`

```moonbit
pub struct BskParams {
  base_log : Int
  level    : Int
}

pub struct BootstrappingKey {
  params       : BskParams
  n_in         : Int
  n_trlwe      : Int
  trgsw_params : TrgswParams
  trgsw_data   : Array[TrgswCiphertext]
  s_bits       : Array[Bool]
  key_trlwe    : TrlweKey
  sigma_trlwe  : Float
}

pub fn bsk_generate(
  p         : TfheParams,
  key_lwe   : LweKey,
  key_trlwe : TrlweKey,
  base_log  : Int,
  level     : Int,
  sigma_bsk : Float,
  rng       : CsPrng,
) -> BootstrappingKey
```

`bsk_generate` produces a `BootstrappingKey` by encrypting each bit of the LWE secret key into a `TrgswCiphertext`. This is the core object used to lift an LWE ciphertext into the TRLWE domain during blind rotation.

### 4. Programmable bootstrap & gates

Module: `ZSeanYves/MoonTFHE/bootstrap`

```moonbit
pub struct Lut2 {
  f0 : Int
  f1 : Int
}

pub struct LutN {
  table : Array[Int]
}

// unary PBS
pub fn programmable_bootstrap(
  p      : TfheParams,
  bk     : BootstrappingKey,
  ct_in  : LweCiphertext,
  f_true : Int,
  f_false: Int,
) -> LweCiphertext

pub fn tfhe_id(
  p  : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext

pub fn tfhe_not(
  p  : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext

// binary PBS
pub fn programmable_bootstrap_bin(
  p     : TfheParams,
  bk    : BootstrappingKey,
  ct_in : LweCiphertext,
  lut   : LutN,
) -> LweCiphertext

// Boolean gates using PBS
pub fn tfhe_xnor( ... ) -> LweCiphertext
pub fn tfhe_xor ( ... ) -> LweCiphertext
pub fn tfhe_nand( ... ) -> LweCiphertext
pub fn tfhe_and ( ... ) -> LweCiphertext
pub fn tfhe_or  ( ... ) -> LweCiphertext
```

At the moment:

* `programmable_bootstrap` and `programmable_bootstrap_bin` internally call **oracle blind rotation**, which directly sees the secret key.
* This is perfect for **debugging correctness and noise**, but **not yet a real homomorphic evaluation path**.
* The TRGSW-based blind rotation implementation is already present and will replace the oracle path once stabilised.

---

## 🧪 Example: Toy Boolean Circuit over Encrypted Bits

This is a **typical usage pattern** you can follow in experiments. It deliberately mirrors the test code in the library.

> Goal: encrypt `x`, `y`, `z` as bits, compute
> `f(x,y,z) = (x AND y) XOR z`
> using TFHE gates, then decrypt.

```moonbit
use ZSeanYves/MoonTFHE/params.{TfheParams, tfhe_params_small_trlwe}
use ZSeanYves/MoonTFHE/rng.{CsPrng, csprng_new}
use ZSeanYves/MoonTFHE/lwe.{LweKey, LweCiphertext, lwe_key_new, lwe_encrypt, lwe_decrypt}
use ZSeanYves/MoonTFHE/trlwe.{TrlweKey, trlwe_key_new}
use ZSeanYves/MoonTFHE/key.{KeySwitchKey, ksk_generate, ksk_apply}
use ZSeanYves/MoonTFHE/bsk.{BootstrappingKey, bsk_generate}
use ZSeanYves/MoonTFHE/bootstrap.{tfhe_and, tfhe_xor}

let p : TfheParams = tfhe_params_small_trlwe()
let rng : CsPrng = csprng_new(0xDEAD_BEEF)

let key_lwe_in  = lwe_key_new(p.n_lwe_in,  rng)
let key_lwe_out = lwe_key_new(p.n_lwe_out, rng)
let key_trlwe   = trlwe_key_new(p.n_trlwe, rng)

let ksk : KeySwitchKey = ksk_generate(p, key_lwe_in, key_lwe_out, rng)
let bk  : BootstrappingKey =
  bsk_generate(p, key_lwe_out, key_trlwe,
               p.bk_base_log, p.bk_level,
               3.2, rng)

let sigma_enc : Float = p.sigma_lwe
let x_plain = true
let y_plain = false
let z_plain = true

let cx_in : LweCiphertext = lwe_encrypt(key_lwe_in, x_plain, sigma_enc, rng)
let cy_in : LweCiphertext = lwe_encrypt(key_lwe_in, y_plain, sigma_enc, rng)
let cz_in : LweCiphertext = lwe_encrypt(key_lwe_in, z_plain, sigma_enc, rng)

let cx = ksk_apply(p, ksk, cx_in)
let cy = ksk_apply(p, ksk, cy_in)
let cz = ksk_apply(p, ksk, cz_in)

let c_and : LweCiphertext = tfhe_and(p, bk, cx, cy)
let c_f   : LweCiphertext = tfhe_xor(p, bk, c_and, cz)

let f_dec : Bool = lwe_decrypt(key_lwe_out, c_f)
```

Notes:

* With the current oracle PBS path you should treat this as **“encrypted computation with a debugger attached”**.
* Once `_blind_rotate_trgsw` is wired into `programmable_bootstrap`, the same user-facing API is expected to become a genuine homomorphic evaluation.

---

## ❗ Limitations & Disclaimer

* The project focuses on **clarity, tests and experimentation**, not performance or production hardening.
* Many components (especially full PBS and the gate stack) are still undergoing debugging:

  * Tests may fail.
  * Noise may grow too quickly.
  * Different paths (oracle vs TRGSW) may disagree.
* Polynomial arithmetic is implemented naively and will be replaced with NTT-based versions in the future.
* Parameter presets are chosen for **didactic value**, not for cryptographic security.

> **Do not use MoonTFHE to protect sensitive data.**

---

## 🧪 Running Tests

```bash
moon test -p ZSeanYves/MoonTFHE -i 10
```

Representative tests include:

* Sanity checks for LWE/TLWE/TRLWE enc/dec under zero noise.
* TRGSW gadget decomposition and external product consistency tests.
* Oracle vs TRGSW blind-rotation checks.
* Oracle XNOR truth-table tests.

Some tests are explicitly marked as **debug / experimental** and are expected to fail while the TRGSW path is under construction.

---

## 📜 License

Licensed under **Apache-2.0**. See `LICENSE` for details.

© 2025 ZSeanYves. All rights reserved.
