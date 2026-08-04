# MoonTFHE

[English](README.mbt.md)

[![MoonTFHE CI](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml/badge.svg)](https://github.com/ZSeanYves/MoonTFHE/actions/workflows/moontfhe-ci.yml)

MoonTFHE 是使用 MoonBit 编写的 TFHE 研究实现。仓库正在从停止维护的教学原型，重建为具有明确客户端/服务端密钥边界、可独立验证的库。

> 安全状态：**研究版本，不可用于生产或敏感数据**。Boolean Core 的正确性和
> CI 门槛已通过，但性能门槛以及独立密码学和侧信道审计尚未完成。

## 当前状态

目前可维护基线包含 Torus32、typed LWE/GLWE/GGSW/KSK、固定点 CDT 噪声、
安全熵和 RFC8439 随机流、不含秘密的 BSK、Fourier external product、盲旋转、
PBS->KS，以及稳定的 NAND/NOT/AND/OR/XOR/XNOR/MUX 和 Boolean LUT API。

仍然存在以下限制：

- estimator 的 GLWE 结果采用明确记录的 flattened-LWE 近似；
- portable 标准路径只承诺 reference 语义，不承诺性能；
- 尚不能作出经过外部审计的 110 位或 128 位安全声明；
- 侧信道攻击防护。

维护中的 `src/boolean` 门面提供不透明的 `ClientKey`、`ServerKey`、`Ciphertext`
和布尔门 API。native `generate_keys` 支持固定的 110/128 参数；portable 需要可信
host entropy adapter，否则返回结构化 `UnsupportedBackend`。

`ServerKey` 只包含加密 GGSW/KSK、参数、KeyId 和可重建 Fourier 状态。
正式格式为 `MBCT v3`、`MBKS v2` 和 AES-256-GCM 保护的 `MTSK v2`；旧格式
直接返回 `UnsupportedVersion`。

最新同机证据中，PBS/NAND 相对固定 tfhe-rs Boolean harness 约为 `4.2x`；
native steady-state PBS 零堆分配，两套参数各 1,000-step 连续随机电路均通过。
无除法旋转优化已经完成差分测试，但尚未达到要求的 2x 性能目标。

当前仓库版本为 `0.2.0-research`，不是 RC，也不是生产安全版本。

## 构建与测试

安装当前 MoonBit 工具链后运行：

```bash
moon check --target all --warn-list +73
moon test --target native
moon info --target all
moon fmt --check
```

CI 会在 `wasm`、`wasm-gc`、`js` 和 `native` 四个后端运行测试。

## Boolean 示例

```moonbit
let (client, server) = generate_test_keys(boolean_test_parameters(), 0x50464F).unwrap()
let result = server.nand(client.encrypt(true), client.encrypt(false)).unwrap()
assert_eq(client.decrypt(result).unwrap(), true)
```

该构造器仅供确定性测试；生产代码使用 `generate_keys`。

## 路线图

破坏性的 P0-P6 改造计划见 [`docs/maintenance-roadmap.md`](docs/maintenance-roadmap.md)，测试分类与 oracle/reference 的边界见 [`docs/testing.md`](docs/testing.md)。

目标架构参考成熟 TFHE 库：客户端秘密密钥、只含评估材料的服务端密钥、不透明布尔密文、经过校验的参数、安全熵源与采样器、真实盲旋转，以及独立生成的测试夹具。

## 许可证

Apache-2.0，见 [`LICENSE`](LICENSE)。
