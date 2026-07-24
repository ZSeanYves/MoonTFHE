# Boolean Core B7 审计

审计日期：2026-07-24。审计对象：`54d9498` 及本次 B7 检查。结论：**不允许发布 RC，也未达到 85% 硬门槛**。

## 硬门槛

| 门槛 | 结果 | 证据与缺口 |
|---|---:|---|
| 生产路径不含 SplitMix64/CLT | 部分通过 | 新分层包通过 `tools/security-audit/check.sh`；生产 `generate_keys` 尚未接通，因此不能据此声称完整生产路径安全。 |
| 110/128 参数有可复现 estimator 输入输出 | 未通过 | fixture 固定了 tfhe-rs commit 和参数 metadata，但 `estimator_status` 仍为 `metadata-only`，没有本地格密码 estimator 输出。 |
| 标准参数 PBS/NAND/随机电路 | 未通过 | tiny zero-noise Boolean backend 通过门真值表；110/128 参数不执行生产 keygen，随机电路只有 32 次 NAND，不是 1000+ 标准参数电路。 |
| ServerKey/序列化不含秘密 | 通过当前边界 | `ServerKey` 只含实验 BSK，`BootstrappingKey` 只含 GGSW/KSK；当前只序列化 ciphertext，client/server key 均无序列化 API。 |
| all-target/FFI/benchmark CI | 未通过完整定义 | 四 MoonBit 后端、native entropy FFI 和 benchmark CI 通过；Rust FFT wrapper、`cargo test` 和 tfhe-rs 同机基准不存在。 |

硬门槛未全部通过，所以无论加权分数是多少，都不能发布 RC 或删除 compatibility API。

## 加权评分

| 领域 | 得分 | 说明 |
|---|---:|---|
| 正确性 | 22/35 | reference arithmetic、sample extraction、实验 PBS 和完整布尔门真值表已覆盖；标准参数、任意 LUT、连续 PBS 和 1000+ 电路未覆盖。 |
| 安全基础 | 11/25 | native OS entropy、ChaCha20 DRBG、bounded discrete Gaussian 和 secret-free server fields 已有；生产 keygen、分布证明、估计器和侧信道工作缺失。 |
| Boolean API | 10/15 | 稳定 facade、结构化错误、NAND/NOT/AND/OR/XOR/XNOR/MUX 和 ciphertext envelope 已有；LUT 与 key serialization 未完成。 |
| 性能 | 4/15 | 有 reference benchmark 和小系数 MoonBit FFT candidate；无 Fourier BSK、scratch reuse、Rust FFI 或 tfhe-rs 对比。 |
| 测试/文档/维护性 | 8/10 | 四后端 CI、59 个 native tests、fixture/security checks 和安全警告已建立；缺少真实 estimator、cargo job 和标准参数失败率测试。 |
| 合计 | **55/100** | 因硬门槛失败，此分数只表示研究原型进展，不是发布成熟度。 |

## 对比 tfhe-rs 后的阻断项

1. 把 `generate_keys` 接到安全 entropy、独立 mask/noise streams、标准 LWE/GLWE/GGSW/PBS 数据流；失败必须返回结构化错误。
2. vendoring 固定版本的安全估计器，生成 MoonTFHE 自己的 110/128 security bits、failure probability 和 noise margin。
3. 将 GGSW 从 shape-only 实现升级为标准 gadget encryption/external product，支持任意固定 LUT，并在服务端完全不访问秘密。
4. 接入固定版本 Rust FFT C ABI，加入 Fourier BSK、scratch reuse、reference differential tests 和同机 tfhe-rs benchmark。
5. 完成 server-key 显式格式与 `SecretExport` opt-in 格式；checksum 必须升级为适合威胁模型的完整性方案。
6. 标准参数下执行 1000+ 随机布尔电路、多次连续 PBS、噪声预算及失败率统计，然后才重新评分。
