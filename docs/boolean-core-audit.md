# Boolean Core C13 审计

审计日期：2026-07-25。审计对象：`e1abd2d` 及 C7-C12 冲刺提交。结论：**研究版本提升到 72/100，但仍不允许发布 RC，也未达到 85% 硬门槛**。

## 硬门槛

| 门槛 | 结果 | 证据与缺口 |
|---|---:|---|
| 生产路径不含 legacy RNG/CLT | 通过现有代码边界 | root legacy 包、SplitMix/Float Gaussian/旧 PBS 已删除；`tools/security-audit/check.sh` 覆盖全部 maintained package。标准生产 keygen 尚不存在，因此这不是完整安全声明。 |
| 110/128 参数有可复现 estimator 输入输出 | 未通过 | 输入、commit、noise fixture hash 和结构化输出已固定；OCI digest 仍为 sentinel，输出状态为 `not_run`，安全位数/失败率/noise margin 均为空。 |
| 标准参数 PBS/NAND/随机电路 | 未通过 | typed reference PBS、完整 Boolean LUT 和 toy 门真值表通过；`generate_keys(110/128)` 仍明确返回 `UnsupportedBackend`，没有标准 1000+ 电路和连续 PBS 统计。 |
| ServerKey/序列化不含秘密 | 部分通过 | `ServerKey` 只持有 typed `BootstrapKey`，inspection 不暴露 secret；ClientKey 的 MTSK export/import 使用 AES-GCM。MBKS payload 仍只是结构标记，尚不能完整反序列化恢复 BSK/KSK。 |
| all-target/FFI/benchmark CI | 部分通过 | 四 MoonBit 后端、RustFFT/AES-GCM、native entropy、full-width convolution 和 batched external-product ABI 均通过；没有 Fourier BSK、标准 PBS 或 tfhe-rs 同机性能矩阵。 |

硬门槛未全部通过，`tools/rc-gate/check.sh` 必须失败，版本必须保持 research release。

## 加权评分

| 领域 | 得分 | 说明 |
|---|---:|---|
| 正确性 | 26/35 | typed LWE/GLWE/GGSW/KSK/PBS、sample extraction、任意 anti-periodic LUT 和完整 toy Boolean 真值表已覆盖；标准参数与失败率统计缺失。 |
| 安全基础 | 17/25 | root legacy 已删除；OS/WebCrypto/host entropy、RFC8439 ChaCha20、固定点量化 CDT、AES-256-GCM、secret-free server fields 已有；生产 keygen、真实 estimator 和独立审计缺失。 |
| Boolean API | 13/15 | 稳定 facade 已直接持有 typed core，旧 API/旧格式已删除；ClientKey import 完成。ServerKey import 和生产标准 keygen 仍缺失。 |
| 性能 | 7/15 | RustFFT 固定版本、16-bit limb、batch external-product ABI 和差分测试已建立；没有 Fourier BSK/PBS 和 tfhe-rs 同机数据。 |
| 测试/文档/维护性 | 9/10 | 四后端 CI、Rust FFI、fixture hash、estimator schema、安全检查和认证失败测试均存在；标准电路/性能回归矩阵缺失。 |
| 合计 | **72/100** | 架构和安全边界已明显收敛，但四个发布阻断项仍然实质存在。 |

## RC 阻断项

1. 实现 native 标准 110/128 `generate_keys`，使用独立 key/mask/noise/BSK streams 和对应 CDT/TUniform 分布。
2. 完成标准 GGSW BSK、Fourier conversion、external product、blind rotation 和 PBS->KS，并使 NAND/所有门走该路径。
3. 固定真实 Sage OCI digest，运行 lattice-estimator，提交非伪造的 security bits、failure probability 和 noise margin，随后才能取消 `reference_only`。
4. 将 MBKS 从结构标记升级为完整公开评估材料格式，实现 `ServerKey::deserialize` 和 malformed/cross-parameter tests。
5. 在 110/128 参数下运行每套 1000+ 随机电路、连续 PBS/失败率统计和与固定 tfhe-rs 的同机性能矩阵。
