# Boolean Core B7 审计

审计日期：2026-07-25。审计对象：`6c84461` 及本次 C0-C3 补强。结论：**不允许发布 RC，也未达到 85% 硬门槛**。

## 硬门槛

| 门槛 | 结果 | 证据与缺口 |
|---|---:|---|
| 生产路径不含 SplitMix64/CLT | 部分通过 | 新分层包通过 `tools/security-audit/check.sh`；生产 `generate_keys` 尚未接通，因此不能据此声称完整生产路径安全。 |
| 110/128 参数有可复现 estimator 输入输出 | 未通过 | fixture 固定了 tfhe-rs commit 和参数 metadata，但 `estimator_status` 仍为 `metadata-only`，没有本地格密码 estimator 输出。 |
| 标准参数 PBS/NAND/随机电路 | 未通过 | 带噪 toy typed PBS 和实验门真值表通过；110/128 参数不执行生产 keygen，也没有 1000+ 标准参数电路。 |
| ServerKey/序列化不含秘密 | 通过当前边界 | typed `BootstrapKey` 和兼容 `BootstrappingKey` 均只含 GGSW/KSK；MBKS 序列化只遍历加密评估材料，client secret 仅能经显式 AES-GCM `SecretExport` 导出。 |
| all-target/FFI/benchmark CI | 部分通过 | 四 MoonBit 后端、RustFFT/AES-GCM `cargo test`、native entropy、full-width FFT 差分和 benchmark smoke 均通过；标准 PBS/tfhe-rs 同机性能矩阵仍不存在。 |

硬门槛未全部通过，所以无论加权分数是多少，都不能发布 RC 或删除 compatibility API。

## 加权评分

| 领域 | 得分 | 说明 |
|---|---:|---|
| 正确性 | 25/35 | reference arithmetic、sample extraction、typed GGSW/CMUX、typed blind rotation/PBS->KS 和实验布尔门真值表已覆盖；标准参数、完整任意 LUT、连续 PBS 和 1000+ 电路未覆盖。 |
| 安全基础 | 15/25 | OS/WebCrypto/host entropy、RFC8439 ChaCha20、固定点 CDT、AES-256-GCM 和 secret-free server fields 已有；生产 keygen、标准分布证明、估计器和侧信道工作缺失。 |
| Boolean API | 12/15 | 稳定 facade、结构化错误、完整门 API、版本化 ciphertext/server-key 和显式 SecretExport 已有；稳定 facade 仍委托 deprecated root，标准 PBS 尚未接入。 |
| 性能 | 7/15 | RustFFT C ABI、caller-owned scratch、16-bit limb split、full-width differential 和 benchmark smoke 已有；无 Fourier BSK、标准 PBS 或 tfhe-rs 同机对比。 |
| 测试/文档/维护性 | 9/10 | 四后端 CI、Rust FFI tests、fixture/security checks、malformed serialization 和安全警告已建立；缺少真实 estimator 和标准参数失败率测试。 |
| 合计 | **68/100** | typed reference PBS、native providers 和稳定序列化提高了成熟度，但硬门槛仍失败；此分数不是发布成熟度。 |

## 对比 tfhe-rs 后的阻断项

1. 把 `generate_keys` 接到安全 entropy、独立 mask/noise streams、标准 LWE/GLWE/GGSW/PBS 数据流；失败必须返回结构化错误。
2. vendoring 固定版本的安全估计器，生成 MoonTFHE 自己的 110/128 security bits、failure probability 和 noise margin。
3. 将 typed GGSW/PBS 从 toy reference 扩展为标准参数 gadget encryption/external product，支持完整固定 LUT，并在服务端完全不访问秘密；稳定 facade 仍需迁移到该路径。
4. 把现有固定版本 RustFFT C ABI 接到 Fourier BSK/external product，并加入标准 PBS 与 tfhe-rs 同机 benchmark。
5. 为现有 MBKS/SecretExport 增加反序列化/import、版本迁移和跨后端 fixture；继续保持 client secret 只能显式认证加密导出。
6. 标准参数下执行 1000+ 随机布尔电路、多次连续 PBS、噪声预算及失败率统计，然后才重新评分。
