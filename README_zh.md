# MoonTFHE

[English](README.mbt.md)

[![MoonTFHE CI](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml/badge.svg)](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml)

MoonTFHE 是使用 MoonBit 编写的 TFHE 研究实现。仓库正在从停止维护的教学原型，重建为具有明确客户端/服务端密钥边界、可独立验证的库。

> 安全状态：**不可用于生产或敏感数据**。`experimental_boolean_*` 门面为了可复现
> 测试使用确定性的测试专用 ChaCha20 流与零噪声；native 系统熵基础已存在，但尚未
> 接入完整 TFHE 生产密钥生成路径。

## 当前状态

目前可维护基线包含 Torus32 运算、朴素负循环多项式、LWE/TLWE/TRLWE 加解密、有符号高位密钥切换、TRGSW 外积、样本提取、不含秘密的加密 BSK、真实 TRGSW 盲旋转、PBS->KS，以及实验性的 unary/NAND/AND/OR/XOR/XNOR/MUX 门。

以下能力仍明确标记为实验性或未完成：

- 生产级参数集和完整安全估计；
- 所有后端的安全随机客户端密钥门面；
- 110 位或 128 位安全声明；
- 侧信道攻击防护。

维护中的 `src/boolean` 门面提供不透明的 `ClientKey`、`ServerKey`、`Ciphertext` 和布尔门 API。生产 `generate_keys` 在安全密钥生成路径接通前会明确返回 `UnsupportedBackend`。

旧 oracle 现在只存在于 `oracle_wbtest.mbt`，显式接收测试秘密，只能作为参考。`BootstrappingKey` 现在只包含加密 GGSW、维度元数据和加密 KSK，是当前 PBS 路径使用的评估对象，但还不是经过完整加固的生产服务端密钥。稳定门面在 legacy `MTFH` payload 外包装了带版本、参数、维度、长度和校验和的 `MBCT` 密文格式，但不会序列化客户端秘密或服务端密钥。

## 构建与测试

安装当前 MoonBit 工具链后运行：

```bash
moon check --target all --warn-list +73
moon test --target native
moon info --target all
moon fmt --check
```

CI 会在 `wasm`、`wasm-gc`、`js` 和 `native` 四个后端运行测试。

## 实验示例

以下流程是确定性的，API 特意使用 `experimental_*` 命名，避免被误认为安全生产路径。

```moonbit
let client = experimental_keygen(64, 3.0, 0x4D4F4F4E)
let encrypted = client.encrypt(true)
let encrypted_not = encrypted.not()
assert_eq(client.decrypt(encrypted_not), false)
```

完整实验性 Boolean 工作流也可通过公开 API 运行，服务端运算不接收客户端秘密：

```moonbit
let (client, server) = experimental_boolean_keygen(0x50464F)
let result = server.nand(client.encrypt(true), client.encrypt(false)).unwrap()
assert_eq(client.decrypt(result).unwrap(), true)
```

## 路线图

破坏性的 P0-P6 改造计划见 [`docs/maintenance-roadmap.md`](docs/maintenance-roadmap.md)，测试分类与 oracle/reference 的边界见 [`docs/testing.md`](docs/testing.md)。

目标架构参考成熟 TFHE 库：客户端秘密密钥、只含评估材料的服务端密钥、不透明布尔密文、经过校验的参数、安全熵源与采样器、真实盲旋转，以及独立生成的测试夹具。

## 许可证

Apache-2.0，见 [`LICENSE`](LICENSE)。
