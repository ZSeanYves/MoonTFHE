# MoonTFHE 维护评估与升级路线

评估日期：2026-07-24。

实施进度：基线、P0、P1、P2 熵源基础、P3 真实 PBS、P4 参数元数据、P5 native benchmark 基线和 P6 实验性 Boolean facade 已分阶段推送。安全参数估计、跨后端生产熵源、FFT/NTT 性能后端和生产级发布仍未完成。

## 第二阶段 B0-B7 执行记录

当前按 Boolean Core 补强计划执行。B0-B6 已逐阶段提交、推送并通过远端 CI；B7 审计结论为 55/100，因硬门槛失败而禁止 RC。阶段提交和 CI 记录以 Git 历史及 GitHub Actions 为准。

2026-07-25 的 C 阶段补强已经接入 OS/WebCrypto/host entropy、RFC8439
ChaCha20、固定点 CDT、RustFFT/AES-GCM C ABI、版本化 key envelopes，以及
typed GGSW/CMUX/blind-rotation/PBS->KS reference pipeline。重新审计为 68/100；
110/128 estimator、标准参数 BSK/PBS、Fourier BSK 和 1000+ 标准电路仍是硬
阻断，因此 `generate_keys` 继续安全失败，不能发布 RC。

本轮新增的稳定 facade 是 `src/boolean`，但它目前只对
`boolean_test_parameters()` 提供确定性测试 keygen。110/128 命名参数已经有固定
metadata fixture，不能被解释为 MoonTFHE 已证明的安全参数。`generate_keys` 对生产参数
仍返回 `UnsupportedBackend`，这是刻意保留的安全失败行为。

B6 的 `MBCT` 只序列化密文，包含 magic、version、parameter code、dimension、key tag、
payload length 和 checksum。checksum 只用于完整性检测，不提供认证加密；client secret
和 server key 没有默认导出 API。B7 必须审计这些边界，并在生产 keygen、参数 estimator、
FFT FFI 和完整 LUT/PBS 尚未完成时阻止 RC 发布。

本文件区分两件事：当前仓库已经恢复到可编译、可测试状态；当前密码学实现仍是研究原型，不能用于真实数据，也尚未满足最初任务要求中的完整性与安全性。

## 对照基线

- MoonTFHE：当前工作树，MoonBit `0.1.20260713` / `moonc 0.10.4`。
- TFHE-rs：主分支提交 [`640911e`](https://github.com/zama-ai/tfhe-rs/commit/640911eba7a394f078fa5d7d14e146105757e34f)，源码版本 `1.7.0`；对外发布版本以 [TFHE-rs Releases](https://github.com/zama-ai/tfhe-rs/releases) 为准。
- 算法与 API 参考：[TFHE-rs](https://github.com/zama-ai/tfhe-rs)、[TFHE-rs 文档](https://docs.zama.ai/tfhe-rs)、[Concrete FFT](https://github.com/zama-ai/concrete-fft)。
- 方案参考：[TFHE 2016](https://eprint.iacr.org/2016/870)、[TFHE 2020/ePrint](https://eprint.iacr.org/2018/421)。

## 当前实现判断

当前数据流是：

```text
Torus32 / 多项式 / 随机数
        -> LWE + TLWE/TRLWE
        -> KSK + TRGSW + BSK
        -> oracle PBS / 试验性 blind rotation
        -> XNOR/XOR 原型
```

已有价值：Torus32 运算、负循环多项式运算、LWE/TRLWE 往返、样本提取、KSK、TRGSW 外积结构和 PBS 各步骤均有可读的教学代码与确定性测试。

必须明确的限制：

1. 生产 PBS 已走 TRGSW blind rotation 和 PBS->KS；但当前实现仍是朴素整数后端，尚未完成标准参数下的噪声/失败概率验证。
2. `BootstrappingKey` 已移除 `s_bits`、`key_trlwe`，只保留加密 GGSW 和加密 KSK；构造函数仍在客户端侧接收秘密。
3. `tfhe_nand`、`tfhe_and`、`tfhe_or` 已可运行，但只对实验性的 `±1/8` 编码和小参数向量作出正确性保证。
4. `CsPrng` 仍是 legacy SplitMix64；native 已有独立 `SecureRng` OS 熵适配，旧 LWE/TRLWE API 尚未全面切换到它。
5. 高斯噪声的 legacy 路径仍是 CLT 近似；`SecureRng::gaussian` 是过渡实现，不替代参数化 TFHE 分布。
6. 两套参数仍是实验参数，没有安全估计、失败概率、噪声预算或 110/128 位安全声明依据。
7. `ExperimentalBooleanClientKey`/`ExperimentalBooleanServerKey` 已提供外部 NAND 流程和不透明密文；它仍是 deterministic/zero-noise 原型，不是生产级客户端 facade。
8. oracle 已移到白盒参考层；剩余测试仍需要独立 tfhe-rs 密文夹具和更广泛随机电路覆盖。

## 与 TFHE-rs 的关键差距

| 领域 | MoonTFHE 当前实现 | TFHE-rs 的成熟做法 | 结论 |
|---|---|---|---|
| 密钥边界 | BSK 只含加密 GGSW/KSK；构造仍在客户端接收秘密 | `ClientKey` 保密，公开 `ServerKey` 只含 Fourier BSK、KSK 和执行顺序 | P3 已移除秘密字段，仍需高层 facade |
| 随机数 | 单个 SplitMix64 同时生成密钥、mask、噪声 | 系统 seeder；秘密随机与加密随机分离；mask 与误差使用不同 CSPRNG 状态 | 必须替换，并保留独立的确定性测试 RNG |
| 噪声 | CLT 近似离散高斯 | 显式 `DynamicDistribution`，支持 Gaussian/TUniform，并有分布与噪声测试 | 不能仅调参数，需重写采样层 |
| 参数 | 裸 `Int/Float` 参数包 | 维度、分解基、层数、模数、分布均为强类型；预设附带安全性和失败概率 | 自定义参数应经过校验，安全预设不可手填猜测 |
| Torus/模数 | 固定 32 位 `Int`，模数隐含 | 泛化到 `u32/u64` 与显式 ciphertext modulus | 第一版可固定 Torus32，但必须封装类型和模数语义 |
| Key switch | 无符号 LSB 分解，缺少标准舍入/有符号分解模型 | 使用 signed decomposer、维度检查和模数检查 | 需按论文/参考实现重写并用向量验证 |
| GGSW/PBS | 标准域数组；生产路径已走真实 blind rotation + sample extraction + KS | 标准 BSK 生成后转 Fourier/NTT 域，真实 blind rotation + sample extraction | 正确性骨架已完成，参数/性能后端仍缺 |
| 多项式性能 | 负循环乘法为 `O(N^2)`，NTT 是空占位 | FFT/FFT128/NTT/Karatsuba 多后端和预分配 scratch buffer | 正确性完成后再优化，优先 FFT 原生后端 |
| API | 已有实验性 Boolean facade；底层结构仍在单包暴露 | 高层 API、Boolean/Shortint API、Core Crypto 分层 | 后续应拆包并把实验性入口替换为安全 facade |
| 测试 | 37 个包内测试，存在弱断言和同路径对照 | 算法测试、噪声分布测试、参数化测试、后端测试、版本化测试 | 先建立规范测试，再替换实现 |

## 建议的破坏性架构

建议废弃当前“所有文件属于一个 `src` 包”的公开形态，按责任拆包：

```text
src/
  torus/          # Torus32、编码、模数切换
  polynomial/     # 负循环环、朴素参考实现、FFT/NTT 后端接口
  random/         # SecureRng、TestRng、噪声分布
  core/lwe/       # LWE 实体、加解密、线性运算
  core/glwe/      # 统一现有 TLWE/TRLWE 命名和实现
  core/ggsw/      # GGSW、分解、外积、CMUX
  core/keyswitch/ # KSK 生成与应用
  core/pbs/       # blind rotation、sample extraction、PBS
  params/         # 经验证的参数与构造校验
  boolean/        # ClientKey、ServerKey、Ciphertext、门 API
```

建议的公开边界：

- `ClientKey`：只在客户端持有 LWE/GLWE secret keys，提供 `generate/encrypt/decrypt`。
- `ServerKey`：只含 BSK/KSK 和参数，不得包含任何 secret key 或明文秘钥位。
- `BooleanCiphertext`：表示不透明，不允许外部任意改字段。
- `BooleanParameters`：优先提供命名安全预设；自定义构造返回校验错误并显式标记为高级/不安全入口。
- `TestRng` 与 `SecureRng`：类型上分离，生产 API 不接受 `TestRng`。
- oracle 解密与 oracle blind rotation：移入仅测试可见的 reference package，生产代码不能导入。

## 实施顺序与验收条件

### P0：冻结诚实基线

- 把会 `panic` 的 NAND/AND/OR 从稳定 API 移除或标为实验 API。
- 将现有 oracle 实现移动到测试参考层。
- 为当前 37 个测试分类：规范测试、回归测试、调试探针；删除无断言测试或补上断言。
- 新增黑盒测试，证明外部包能完成 keygen -> encrypt -> operation -> decrypt。

验收：文档不再宣称完整 FHE；公开 API 不包含“看似可用、实际 panic”的操作。

### P1：先写规范和参考测试

- 为 Torus 编码、模数切换、有符号 gadget decomposition、样本提取写边界测试。
- 用朴素多项式实现作为 reference backend，FFT/NTT 结果必须逐项对齐。
- 固定一个 tfhe-rs 版本生成互操作测试夹具；记录参数、随机种子、明文相位和期望解密结果。
- NAND 对全部四种输入做属性测试；随机电路测试覆盖多次自举。

验收：新实现可以被替换而不依赖旧实现“自己证明自己”。

### P2：重建安全基础层

- 以 `Torus32` 封装 32 位环面元素，集中处理 wrapping arithmetic。
- 接入操作系统熵与经过审查的 CSPRNG；若 MoonBit 标准库缺少所需能力，使用原生 FFI 封装系统随机源和成熟 C 实现。
- 实现经验证的 Gaussian 或 TUniform 采样，不自行发明近似分布。
- 合并重复的 TLWE/TRLWE 代码，统一采用 GLWE/TRLWE 术语并保留迁移说明。

验收：生产路径无 SplitMix64；统计测试、已知向量、跨后端整数语义测试通过。

### P3：重写 KSK、GGSW 与真实 PBS

- [x] 实现与 GGSW 权重一致的高位 Torus decomposition 和 key switching。
- [x] 按 GLWE size 和 decomposition level 建模 GGSW 矩阵。
- [x] BSK 只保存加密后的 GGSW/KSK 数据，移除 `s_bits`、`key_trlwe`。
- [x] 真实执行 accumulator 初始化、blind rotation、sample extraction；oracle 只用于测试对照。
- [x] 选择 PBS->KS 顺序并将 KSK 固定在 BSK 中。
- [ ] 在标准参数、随机相位和完整噪声预算下验证成功率。

验收：在不访问任何 secret key 的服务端完成 ID、NOT、NAND；每个门的全部输入和随机电路均正确。

### P4：参数与安全声明

- [x] 导入 tfhe-rs Boolean 默认/强参数的可追溯 reference records 和 MoonBit 构造器。
- [x] 记录 LWE/GLWE 维度、噪声分布、PBS/KSK 分解、目标失败概率和上游 commit。
- [x] tiny/test 参数经过校验 API 标记为实验参数，不能误认为安全预设。
- [ ] 集成可复现的本地安全估计器并生成 MoonTFHE 自己的 128/110 位证明；当前 reference 构造器仍不能继承上游安全声明。

验收：安全数字可由脚本和固定版本估计器复现，而不是来自经验注释。

### P5：性能后端

- [x] 保留朴素 `O(N^2)` 后端作正确性基准，并记录 native 基线。
- 原生后端优先实现 FFT negacyclic convolution、Fourier BSK 和 scratch buffer 复用；再评估 NTT。
- [x] 加入可重复的 polynomial/external-product benchmark smoke；完整 keygen/KSK/PBS/门吞吐基准仍待补齐。
- 优化必须以基准和内存峰值为依据，不在算法尚未正确前做 SIMD 微调。

验收：发布每个标准参数集的时间、内存、密钥/密文大小；性能回归进入 CI。

### P6：产品化 API 与发布

- [x] 提供明确标为 experimental 的 Boolean facade；底层 core API 仍需后续拆包。
- [x] 增加 `MTFH` 密文格式、版本号、长度/维度/key-tag 校验，并不提供 secret/server key 序列化。
- [x] CI 覆盖 `moon check --target all`、四后端测试、原生安全测试和 benchmark smoke；文档示例仍需独立文档编译 job。
- [x] README 给出可运行的实验性 NAND 示例和安全警告；尚未发布 Mooncakes 新主版本。

验收：外部用户只通过公开 API 即可运行完整 NAND 电路；服务端工件不含秘钥；发布包可复现构建和测试。

## 下一轮建议范围

下一轮不要直接优化 FFT。先完成 P0 + P1，并把“oracle reference”和“production candidate”彻底分离；随后以 BSK 不含秘密、真实 NAND 通过四输入黑盒测试作为 P2/P3 的首个硬目标。这样允许彻底重写内部结构，同时保留可验证的行为基线。
