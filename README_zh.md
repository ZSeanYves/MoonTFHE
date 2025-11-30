# MoonTFHE 自述文件 (中文)

[English](#moontfhe-readme-english) | [简体中文](#moontfhe-自述文件-中文)

---

# 🔐 MoonTFHE：MoonBit 下的 TFHE 同态加密库

[![Build Status](https://img.shields.io/github/actions/workflow/status/ZSeanYves/MoonTFHE/moontfhe-ci.yml)](https://github.com/ZSeanYves/MoonTFHE/actions)
[![License](https://img.shields.io/github/license/ZSeanYves/MoonTFHE)](LICENSE)

**MoonTFHE** 是一个用 MoonBit 编写的、面向研究与教学的 **TFHE（Torus 上的完全同态加密）实现**。
项目目标是把 TFHE 中的核心组件（LWE / TLWE / TRLWE / TRGSW、密钥切换、自举密钥、可编程自举）用 **结构清晰、容易阅读和测试的 MoonBit 代码** 表达出来，方便学习和实验，而不是做成黑盒库。

当前实现已经完成到 **TRGSW 外积核心 + 自举密钥（BSK）构造**；使用 TRGSW 的盲旋转和完整的可编程自举流程仍在持续调试中。

> ⚠️ 本库仅用于 **学习、演示和实验**，不要用于任何真实敏感数据场景。

---

## 🚦 进度与特性

### 已实现

* **数值 / Torus 层**

  * Torus32 定点数表示与辅助函数（`T32_HALF`, `T32_QUARTER` 等）。
  * 模运算与取整工具。

* **随机性与噪声**

  * 轻量可复现的伪随机数发生器 `CsPrng`（SplitMix64）。
  * 用于 LWE / TRLWE 的离散高斯采样。

* **基础加密结构**

  * **LWE**：`LweKey`、`LweCiphertext`，内部提供 `lwe_encrypt` / `lwe_decrypt`。
  * **TLWE**：`TlweKey`、`TlweCiphertext`（环上密文）。
  * **TRLWE**：`TrlweKey`、`TrlweCiphertext`（用于累加器的多项式密文）。

* **TFHE 相关结构**

  * 统一的参数结构 `TfheParams`。
  * **TRGSW**：

    * `TrgswParams`、`TrgswCiphertext`。
    * gadget 分解和 TRGSW ⊗ TRLWE **外积**（盲旋转的代数核心）。
  * **密钥切换（Key-Switch）**：

    * `KskParams`、`KeySwitchKey`。
    * `ksk_generate`、`ksk_apply`。
  * **自举密钥（BSK）**：

    * `BskParams`、`BootstrappingKey`。
    * `bsk_generate` 从 LWE 密钥和 TRLWE 密钥生成 BSK。

* **可编程自举 & 逻辑门（API 雏形）**

  * 查找表：`Lut2`、`LutN`。
  * 一元可编程自举：

    * `programmable_bootstrap(p, bk, ct, f_true, f_false)`。
    * 封装接口 `tfhe_id`、`tfhe_not`。
  * 二元可编程自举：

    * `programmable_bootstrap_bin(p, bk, ct, lut)`。
  * 基于 PBS 的布尔门：

    * `tfhe_xnor`、`tfhe_xor`、`tfhe_nand`、`tfhe_and`、`tfhe_or`。

* **调试辅助**

  * 零噪声参数集，用于追踪精确行为。
  * 基于“oracle 盲旋转”的 PBS（非同态，内部直接使用秘钥）作为对照。
  * 用于对比 TRGSW 外积与 oracle 行为的一组测试。

### 进行中 / 实验性部分

已经有代码实现，但应视作 **实验性**：

* 基于 TRGSW 的盲旋转实现（`_blind_rotate_trgsw`）。
* 使用 TRGSW + BSK 的完整 PBS 流水线。
* 真正走 TRGSW 路径的 `tfhe_*` 布尔门栈。
* 噪声跟踪与更安全的参数预设。

目前 PBS 内部仍大多走 **oracle 盲旋转路径**，即内部直接访问秘钥，所以整体还 **不能视作完整的同态计算实现**。

---

## 📦 安装

```bash
moon add ZSeanYves/MoonTFHE
```

或在 `moon.mod.json` 中加入：

```json
{
  "import": ["ZSeanYves/MoonTFHE"]
}
```

---

## 🧩 模块结构

> 文件名以后可能会微调，但整体结构大致如下：

| 文件                 | 模块              | 说明                                  |
| ------------------ | --------------- | ----------------------------------- |
| `torus.mbt`        | `torus`         | Torus32 表示、常量与加减、编码/解码。             |
| `params.mbt`       | `params`        | `TfheParams` 参数集合与预设。               |
| `rng.mbt`          | `rng`           | `CsPrng` 伪随机数发生器与工具函数。              |
| `math.mbt`         | `math`          | 数值与模运算工具。                           |
| `noise.mbt`        | `noise`         | 噪声采样相关辅助函数。                         |
| `lwe.mbt`          | `lwe`           | `LweKey`、`LweCiphertext` 及 enc/dec。 |
| `tlwe.mbt`         | `tlwe`          | `TlweKey`、`TlweCiphertext`。         |
| `trlwe.mbt`        | `trlwe`         | `TrlweKey`、`TrlweCiphertext`。       |
| `trgsw.mbt`        | `trgsw`         | `TrgswParams`、`TrgswCiphertext`、外积。 |
| `key.mbt`          | `key`           | 密钥切换参数与 `KeySwitchKey`。             |
| `bsk.mbt`          | `bsk`           | `BskParams`、`BootstrappingKey` 与构造。 |
| `bootstrap.mbt`    | `bootstrap`     | LUT、可编程自举、布尔门。                      |
| `boostrap_exp.mbt` | `bootstrap_exp` | PBS 实验与调试代码。                        |
| `gates.mbt`        | `gates`         | 额外门电路测试与 oracle 对照。                 |
| `moon.pkg.json`    | —               | MoonBit 包配置。                        |

---

## 🔧 核心数据结构

| 类型                 | 所在模块        | 说明                                    |
| ------------------ | ----------- | ------------------------------------- |
| `TfheParams`       | `params`    | TFHE 所有参数的统一结构。                       |
| `CsPrng`           | `rng`       | 轻量伪随机数发生器。                            |
| `LweKey`           | `lwe`       | LWE 二进制秘钥。                            |
| `LweCiphertext`    | `lwe`       | LWE 密文 `{ a : Array[Int], b : Int }`。 |
| `TlweKey`          | `tlwe`      | TLWE 秘钥（环多项式）。                        |
| `TlweCiphertext`   | `tlwe`      | TLWE 密文。                              |
| `TrlweKey`         | `trlwe`     | TRLWE 秘钥。                             |
| `TrlweCiphertext`  | `trlwe`     | TRLWE 密文（盲旋转中的累加器）。                   |
| `TrgswParams`      | `trgsw`     | TRGSW 的 base / level / 环维度。           |
| `TrgswCiphertext`  | `trgsw`     | TRGSW 密文，编码一个控制比特。                    |
| `KskParams`        | `key`       | 密钥切换参数 `(base_log, level)`。           |
| `KeySwitchKey`     | `key`       | LWE → LWE 密钥切换密钥。                     |
| `BskParams`        | `bsk`       | 自举密钥参数 `(base_log, level)`。           |
| `BootstrappingKey` | `bsk`       | LWE → TRLWE 自举密钥。                     |
| `Lut2`             | `bootstrap` | 长度为 2 的查找表。                           |
| `LutN`             | `bootstrap` | 通用查找表。                                |

---

## 🔌 API 概览

下面按照“实际使用场景”整理最常用的一些入口。当前有一部分工具函数仍然是内部使用（tests 中大量调用），后续会在库稳定后逐步向外导出。

### 1. 参数预设

模块：`ZSeanYves/MoonTFHE/params`

```moonbit
pub struct TfheParams { ... }

pub fn tfhe_params_small_trlwe() -> TfheParams
pub fn tfhe_params_tiny_trlwe()  -> TfheParams
```

* `tfhe_params_small_trlwe()`：一个“结构完整但尺寸较小”的参数集，适合做实验。
* `tfhe_params_tiny_trlwe()`：更小的玩具参数，用于调试。

### 2. 密钥切换（Key-Switch）

模块：`ZSeanYves/MoonTFHE/key`

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

* `ksk_generate`：从输入秘钥 `key_in` 和输出秘钥 `key_out` 生成一个密钥切换密钥。
* `ksk_apply`：把一个在 `key_in` 下加密的 LWE 密文，转换到 `key_out` 对应的密文（保持明文不变，只改变密钥空间）。

### 3. 自举密钥（BSK）

模块：`ZSeanYves/MoonTFHE/bsk`

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

`bsk_generate` 会把 LWE 秘钥的每一位 `s[i]` 加密成一个 `TrgswCiphertext`，得到自举密钥 `BootstrappingKey`，用于把 LWE 密文提升到 TRLWE 域做盲旋转。

### 4. 可编程自举与布尔门

模块：`ZSeanYves/MoonTFHE/bootstrap`

```moonbit
pub struct Lut2 {
  f0 : Int
  f1 : Int
}

pub struct LutN {
  table : Array[Int]
}

// 一元 PBS
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

// 二元 PBS
pub fn programmable_bootstrap_bin(
  p     : TfheParams,
  bk    : BootstrappingKey,
  ct_in : LweCiphertext,
  lut   : LutN,
) -> LweCiphertext

// 基于 PBS 的布尔门
pub fn tfhe_xnor( ... ) -> LweCiphertext
pub fn tfhe_xor ( ... ) -> LweCiphertext
pub fn tfhe_nand( ... ) -> LweCiphertext
pub fn tfhe_and ( ... ) -> LweCiphertext
pub fn tfhe_or  ( ... ) -> LweCiphertext
```

当前实现中：

* `programmable_bootstrap` / `programmable_bootstrap_bin` 内部仍使用 **oracle 盲旋转**，调试时可以看到真实相位与明文编码的关系。
* 一旦基于 TRGSW 的盲旋转稳定，将把 PBS 的内部实现切换到真正同态路径，而不改变这些对外接口。

---

## 🧪 使用示例：在密文上计算布尔电路

场景：

> 输入比特 `x, y, z`，加密后在密文上计算
> `f(x,y,z) = (x AND y) XOR z`，最后解密得到结果。

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

let ksk = ksk_generate(p, key_lwe_in, key_lwe_out, rng)
let bk  = bsk_generate(p, key_lwe_out, key_trlwe,
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

实际调试时，你可以：

* 把噪声参数调成 0（或很小），直接观察 `LWE phase` 与明文编码的关系；
* 切换 PBS 内部使用的路径（oracle vs TRGSW），对比两种实现输出是否一致。

---

## ❗ 限制与说明

* 本库主要目标是 **便于阅读与实验**：

  * 代码更偏“直白”和“可追踪”，而不是极致性能；
  * 参数预设偏“小”“不安全”，方便跑完整流程。
* 完整自举与门电路栈仍在开发中：

  * 某些测试当前是预期失败的（标注为 debug / exp）；
  * 噪声增长暂未做严格分析与控制；
  * oracle 路径与 TRGSW 路径在早期可能会出现不一致。
* 多项式运算目前仍是朴素实现，后续会逐步替换成 NTT 等更高效的实现。

> **再次强调：请勿用 MoonTFHE 处理任何真实世界的隐私数据或安全业务。**

---

## 🧪 运行测试

```bash
moon test -p ZSeanYves/MoonTFHE -i 10
```

典型测试包括：

* LWE/TLWE/TRLWE 在零噪声下的 enc/dec 正确性；
* TRGSW gadget 分解与外积的一致性测试；
* oracle 盲旋转与 TRGSW 盲旋转结果对比；
* `gates.mbt` 中 oracle XNOR 等真值表测试。

部分测试是特意用来做“调试断言”的，在当前开发阶段预期是会失败的。

---

## 📜 协议

本项目使用 **Apache-2.0** 协议开源，详见 `LICENSE`。

© 2025 ZSeanYves. 保留所有权利。
