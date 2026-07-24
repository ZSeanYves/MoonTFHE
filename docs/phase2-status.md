# 第二阶段状态

截至 2026-07-24，B0-B6 已分别提交、推送并通过 GitHub Actions；B7 审计已完成并阻止 RC 发布。

已经落地的内容包括：

- 分层 `torus`、`polynomial`、`random`、`params`、`core/glwe`、`core/ggsw` 和 `boolean` 包。
- Torus32 wrapping arithmetic、显式模数、参考负循环乘法、sample extraction 基础和强类型 GLWE/GGSW 形状。
- native OS entropy + ChaCha20 风格 DRBG 接口；测试 RNG 与生产 RNG 类型路径分离。
- 固定 tfhe-rs commit 的 110/128 参数 metadata fixture 和 CI 校验脚本。
- MoonBit FFT candidate 与 reference multiplication differential tests。
- 不透明 Boolean facade、NAND/NOT/AND/OR/XOR/XNOR/MUX、MBCT ciphertext envelope。

当前不能宣称已经达到计划的 85% 硬门槛：

1. `generate_keys` 对生产参数仍返回 `UnsupportedBackend`，所以安全熵源尚未接入完整 TFHE keygen/encryption/PBS 路径。
2. 根包的实验 PBS 仍使用 zero-noise test parameters；标准参数下的失败概率和连续 PBS 统计尚未建立。
3. 参数 estimator 当前是可审查 metadata verifier，不是已经 vendored 的格密码安全估计器。
4. FFT candidate 只覆盖 reference coefficient range；Rust `concrete-fft` C ABI、Fourier BSK 和 scratch reuse 尚未实现。
5. 只有 ciphertext 可序列化；client secret/server key 的显式格式和结构化导入导出仍待完成。

因此本文件是实施状态记录，不是安全认证或发布声明。B7 当前评分为 55/100 且多个硬门槛失败，仍必须保留“未经独立审计、不可用于生产敏感数据”的警告。具体见 `docs/boolean-core-audit.md`。
