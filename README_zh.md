# 🔐 MoonTFHE：基于 MoonBit 的全同态加密（TFHE）实现

[English](https://github.com/ZSeanYves/MoonTFHE/blob/main/README.md) | [简体中文](https://github.com/ZSeanYves/MoonTFHE/blob/main/README_zh_CN.md)

[![Build Status](https://img.shields.io/github/actions/workflow/status/ZSeanYves/MoonTFHE/moontfhe-ci.yml)](https://github.com/ZSeanYves/MoonTFHE/actions)
[![License](https://img.shields.io/github/license/ZSeanYves/MoonTFHE)](LICENSE)

**MoonTFHE** 是一个基于 [**MoonBit**](https://www.moonbitlang.com/) 实现的 **Torus 全同态加密（TFHE）库**。项目以模块化、可测试和可扩展为核心目标，完整实现了 **LWE / TLWE / TRLWE / TRGSW** 密文体系及 **Bootstrapping / 可编程引导（PBS）** 机制。

> ⚠️ 本项目仍处于研究阶段，仅供学习与实验用途。

---

## 🚀 特性

* 实现完整 TFHE 基础结构：**Torus、LWE、TLWE、TRLWE、TRGSW**
* 支持 **Bootstrapping** 与 **可编程引导（Programmable Bootstrapping, PBS）**
* 实现加密布尔门：**NAND / AND / OR / XOR**
* 参数化设计（n、N、σ 可调），便于实验调整
* 高斯与均匀随机采样器（可复现随机性）
* 模块化架构，清晰分层
* 完备的单元测试与属性测试

---

## 📦 安装

```bash
moon add ZSeanYves/MoonTFHE
```

或编辑 `moon.mod.json`：

```json
"import": ["ZSeanYves/MoonTFHE"]
```

---

## 🧩 模块概览

| 文件              | 模块          | 功能说明                            |
| --------------- | ----------- | ------------------------------- |
| `torus.mbt`     | `torus`     | 定义 Torus32 类型及定点换算工具。           |
| `params.mbt`    | `params`    | 参数定义（n、N、σ、μ）。                  |
| `rng.mbt`       | `rng`       | 随机数生成与高斯采样。                     |
| `math.mbt`      | `math`      | 模运算与数值工具函数。                     |
| `lwe.mbt`       | `lwe`       | LWE 密文结构与加解密。                   |
| `tlwe.mbt`      | `tlwe`      | TLWE 密文结构（基于环的 LWE）。            |
| `trlwe.mbt`     | `trlwe`     | TRLWE 密文（多项式环）。                 |
| `trgsw.mbt`     | `trgsw`     | TRGSW 密文，用于引导操作。                |
| `key.mbt`       | `key`       | 密钥与引导密钥生成逻辑。                    |
| `bsk.mbt`       | `bsk`       | Bootstrapping Key 定义与序列化。       |
| `bootstrap.mbt` | `bootstrap` | 引导与可编程引导实现。                     |
| `gates.mbt`     | `gates`     | 基于 PBS 的布尔门封装（NAND/AND/OR/XOR）。 |

---

## 🚀 快速开始

### 加密 → 同态运算 → 解密

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

### 可编程引导（Programmable Bootstrapping）示例

```moonbit
let lut = make_bool_lut(|x| { !x })  // 布尔 NOT 映射表
let ct_z = programmable_bootstrap(params, ct_x, lut, bsk)
let z = lwe_decrypt_bit(sk_lwe, ct_z)
```

---

## 🔧 API 参考

### 🏗 核心类型

| 类型                   | 说明                          |
| -------------------- | --------------------------- |
| `Torus32`            | Torus 上的定点表示。               |
| `LweCt` / `LweSk`    | LWE 密文与密钥。                  |
| `TlweCt` / `TrlweCt` | TLWE/TRLWE 密文，用于引导。         |
| `TrgswCt`            | TRGSW 密文，用于 Blind Rotation。 |
| `BootstrapKey`       | LWE → TRLWE 转换的引导密钥。        |

### 📤 核心函数

| 函数                       | 签名                                                     | 描述             |
| ------------------------ | ------------------------------------------------------ | -------------- |
| `gen_default_params`     | `() -> Params`                                         | 获取默认参数集。       |
| `gen_keys`               | `(Params, seed:Int) -> (LweSk, TrlweSk, BootstrapKey)` | 生成密钥与引导密钥。     |
| `lwe_encrypt_bit`        | `(LweSk, Bool) -> LweCt`                               | 加密布尔比特。        |
| `lwe_decrypt_bit`        | `(LweSk, LweCt) -> Bool`                               | 解密布尔比特。        |
| `bootstrap`              | `(Params, LweCt, BootstrapKey) -> LweCt`               | 标准引导操作。        |
| `programmable_bootstrap` | `(Params, LweCt, Lut, BootstrapKey) -> LweCt`          | 可编程引导操作。       |
| `nand / and / or / xor`  | `(Params, LweCt, LweCt, BootstrapKey) -> LweCt`        | 基于 PBS 的布尔门操作。 |

---

## ⚠️ 错误类型

`TfheError`（一个 `suberror` 枚举）可能在加密或引导中被抛出：

| 错误枚举                | 说明          |
| ------------------- | ----------- |
| `InvalidParams`     | 参数不合法或不匹配。  |
| `NoiseOverflow`     | 解密噪声超出安全范围。 |
| `KeyMismatch`       | 密钥或引导密钥不匹配。 |
| `LutOutOfRange`     | PBS 查表超出范围。 |
| `NotImplementedYet` | 功能尚未实现。     |

---

## 🧭 常见用法

```moonbit
// 布尔门组合
let a = lwe_encrypt_bit(sk_lwe, true)
let b = lwe_encrypt_bit(sk_lwe, true)
let c = xor(params, a, b, bsk)
let result = lwe_decrypt_bit(sk_lwe, c)
assert(result == false)

// 链式引导（Bootstrapping）
let refreshed = bootstrap(params, c, bsk)
let recovered = lwe_decrypt_bit(sk_lwe, refreshed)
```

---

## ❗ 限制

* 当前仅支持布尔门与小参数集。
* 多项式乘法使用朴素实现（NTT 加速开发中）。
* 噪声估计与模数切换仍为实验性质。
* 尚未进行安全审计，仅供研究使用。

---

## 🧪 测试

运行测试：

```bash
moon test -p ZSeanYves/MoonTFHE -i 10
```

测试内容：

* 布尔门真值表验证（NAND/AND/OR/XOR）
* 引导与密钥切换正确性
* 高斯采样分布一致性
* 参数与噪声范围回归验证

---

## 📜 许可证

采用 **Apache-2.0** 开源许可证。详见 [LICENSE](LICENSE)。

---

© 2025 ZSeanYves. 保留所有权利。
