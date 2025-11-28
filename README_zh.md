# 🔐 MoonTFHE：MoonBit 实现的 TFHE 同态加密库

[English](README.md) | [简体中文](README_zh_CN.md)

[![Build Status](https://img.shields.io/github/actions/workflow/status/ZSeanYves/MoonTFHE/moontfhe-ci.yml)](https://github.com/ZSeanYves/MoonTFHE/actions)
[![License](https://img.shields.io/github/license/ZSeanYves/MoonTFHE)](LICENSE)

**MoonTFHE** 是一个用 [**MoonBit**](https://www.moonbitlang.com/) 编写的、面向研究与学习的 **Torus 上全同态加密（TFHE）** 实现。项目目标是用尽量清晰的 MoonBit 代码搭建 TFHE 的核心组件，方便阅读、调试和后续扩展，而不是直接追求工程级性能或安全性。

目前项目已经推进到 **TRGSW 外积与自举密钥（BSK）构造**；接下来将继续围绕 **TRGSW 接入盲旋转 → 可编程自举（PBS） → 布尔门电路** 这一路径逐步完善。

---

## 🚀 当前状态与特性

### 已完成的部分

- 数值基础层：
  - Torus32 表示及相关辅助函数
  - 基本模运算与舍入工具
  - 高斯/均匀随机数采样器
- 加密原语：
  - **LWE** 密文与秘钥
  - **TLWE / TRLWE** 环上密文
- TFHE 相关结构：
  - **TRGSW** 参数与密文类型
  - 用于 LWE → TRGSW 的 gadget 分解
  - TRGSW ⊗ TRLWE 的 **外积运算**（盲旋转的核心算子）
  - **自举密钥（BSK）** 结构与生成辅助函数
- 自举工具：
  - LUT 结构（`Lut2`、`LutN`）与累加器初始化工具
  - 仅用于对照的 “oracle 版” 盲旋转（非同态，实现正确性参考）
  - 初步的 TFHE 高层 API 结构（`TfheParams`、PBS 辅助函数、门电路桩函数）
- 调试 / 测试辅助：
  - 零噪声参数，方便追踪中间过程
  - 基于 oracle PBS 的 XNOR 门真值表测试，用来验证逻辑线路

### 进行中 / 部分可用

下面这些组件在代码中已经有初步实现，但仍在调试中，**不保证正确性**：

- 基于 TRGSW 的 **盲旋转**（`_blind_rotate_trgsw`）
- 使用 TRGSW + BSK 的端到端 **可编程自举（PBS）**
- 建立在 PBS 之上的同态布尔门（`tfhe_nand`、`tfhe_and`、`tfhe_or`、`tfhe_xor` 等）

当前你应该把它们看成 **实验性质** 代码：可能出现测试失败、噪声爆炸、真值表不匹配等情况。

### 未来计划（Roadmap）

短期内的开发计划大致如下：

1. **稳定 TRGSW 盲旋转路径**
   - 在保留现有 TRGSW 外积实现的基础上，完善累加器旋转路径。
   - 使用 `_blind_rotate_trgsw` 与 `_blind_rotate_oracle` 做广泛对比测试，从零噪声过渡到现实噪声设置。

2. **让 TRGSW 真正“接入”基于盲旋转的 PBS**
   - 使用 `Lut2` / `LutN` 与 TRGSW 盲旋转构建完整的 Programmable Bootstrapping。
   - 让 NAND / AND / OR / XOR 等门在密文上的真值表测试全部通过。

3. **噪声控制与参数预设**
   - 增加噪声估计辅助函数，给出若干“推荐参数配置”，对应不同的安全级别与电路深度。
   - 提供多门电路的示例与噪声预算说明。

4. **性能优化**
   - 用 NTT 优化多项式乘法，替换当前的朴素实现。
   - 在自举关键路径上优化内存布局，减少分配与拷贝。

5. **更高层的 API**
   - 构建更抽象的电路 API 与门组合工具。
   - 更方便的秘钥 / 密文序列化支持。

即便这些目标完成，MoonTFHE 也会主要定位在 **研究与实验** 场景，而不是生产环境。

---

## 📦 安装

```bash
moon add ZSeanYves/MoonTFHE
```

或者手动修改 `moon.mod.json`：

```json
"import": ["ZSeanYves/MoonTFHE"]
```

---

## 🧩 模块概览

> 文件名后续可能会微调，但整体结构大致如下。

| 文件名              | 模块名          | 说明                                                         |
| ------------------- | --------------- | ------------------------------------------------------------ |
| `torus.mbt`         | `torus`         | Torus32 表示与转换辅助函数。                                |
| `params.mbt`        | `params`        | TFHE 参数（`TfheParams`、各维度、μ、σ 等）。                |
| `rng.mbt`           | `rng`           | 随机数发生器与高斯采样。                                    |
| `math.mbt`          | `math`          | 模运算、舍入等通用数值工具。                                |
| `noise.mbt`         | `noise`         | 噪声相关工具函数。                                          |
| `lwe.mbt`           | `lwe`           | LWE 密文 / 密钥与加解密。                                   |
| `tlwe.mbt`          | `tlwe`          | TLWE 密文及基本运算。                                       |
| `trlwe.mbt`         | `trlwe`         | TRLWE 密文（多项式形式）。                                  |
| `trgsw.mbt`         | `trgsw`         | TRGSW 密文、gadget 分解与外积实现。                         |
| `key.mbt`           | `key`           | 秘钥与自举密钥生成逻辑。                                    |
| `bsk.mbt`           | `bsk`           | 自举密钥结构与访问辅助函数。                                |
| `bootstrap.mbt`     | `bootstrap`     | 盲旋转、基于 LUT 的累加器与 PBS 核心逻辑。                  |
| `boostrap_exp.mbt`  | `bootstrap_exp` | 与自举相关的实验性 / 调试代码。                             |
| `gates.mbt`         | `gates`         | 门电路桩函数与调试门（例如 oracle XNOR 测试）。             |
| `moon.pkg.json`     | （包信息）      | MoonBit 包配置。                                             |

---

## 🚀 使用示意（WIP API）

对外 API 仍在调整，下面是一个大致的使用轮廓，仅供参考：

```moonbit
use ZSeanYves/MoonTFHE

// 1. 选择参数（教学/实验用的玩具参数）
let p = tfhe_params_small_trlwe() //你当然也可以按照 TfheParams 自定义

// 2. 生成秘钥（LWE、TRLWE 以及 TRGSW / BSK）
let key_tr = trlwe_key_new(p.n_trlwe, r)
// 3. 加密明文比特
let ct = lwe_encrypt(key_lwe, bit, 3.0, r)

// 4.（未来）在密文上同态计算布尔门
let ct2 = tfhe_id(p, bk, ct)

// 5. 解密输出
let dec = lwe_decrypt(key_lwe, ct2)
```

目前这个流程 **尚不保证** 可以端到端正确运行。建议优先使用仓库中的测试与小型调试代码来单独验证各个组件。

---

## 🔧 核心类型（概念层面）

你会看到的一些关键类型：

| 类型                 | 说明                                                         |
| -------------------- | ------------------------------------------------------------ |
| `Torus32`            | Torus 上的定点表示（以 `Int` 存储）。                       |
| `LweCiphertext`      | 标准 LWE 密文 `{ a : Array[Int], b : Int }`。               |
| `LweKey`             | LWE 秘钥向量。                                               |
| `TlweCiphertext`     | TLWE 密文（环上多项式）。                                   |
| `TrlweCiphertext`    | TRLWE 密文（用于累加器的多项式密文）。                      |
| `TlweKey` / `TrlweKey` | TLWE / TRLWE 对应的秘钥。                                |
| `TrgswCiphertext`    | TRGSW 密文，通过外积控制盲旋转。                            |
| `TrgswParams`        | TRGSW 分解的 base / level 参数。                            |
| `BootstrappingKey`   | LWE → TRLWE 提升所需的一组 TRGSW 密文。                     |
| `TfheParams`         | 高层 TFHE 参数集合。                                        |
| `Lut2` / `LutN`      | 可编程自举中使用的查找表编码。                             |

---

## ⚠️ 限制与声明

- 目前项目重点在于：
  - 原型化盲旋转与 PBS（已验证 TRGSW 外积与 BSK 构造），。
- 包括完整自举与门电路在内的许多部分 **尚未完全打通 / 不保证正确**。
- 多项式运算仍然是朴素实现，后续会用 NTT 做优化。
- 噪声分析与参数选择以实验为主，**不满足实际安全需求**。

> **请不要在生产环境或真实敏感数据上使用 MoonTFHE。**

---

## 🧪 测试

使用如下命令运行测试：

```bash
moon test -p ZSeanYves/MoonTFHE -i 10
```

当前包含的测试主要包括：

- LWE / TLWE / TRLWE 加解密的零噪声 sanity check。
- TRGSW gadget 分解与外积一致性测试。
- oracle 版与 TRGSW 版盲旋转的对比测试（开发中）。
- `gates.mbt` 中基于 oracle 的 XNOR 真值表测试。

其中一部分测试是带有 “实验 / 调试” 性质的，在开发阶段**允许失败**。

---

## 📜 许可证

本项目以 **Apache-2.0** 协议开源，详见 `LICENSE` 文件。

---

© 2025 ZSeanYves. 保留所有权利。
