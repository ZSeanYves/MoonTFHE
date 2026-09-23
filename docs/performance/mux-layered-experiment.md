# MUX 分层性能实验

本实验只讨论 native Boolean MUX，不改变生产门的 PBS 计数。所有输入均为
三个独立生成的密文，避免 `selector == when_false` 时线性组合完全抵消，
从而把退化路径误当成通用 MUX。

## 口径修正

固定 tfhe-rs commit `640911eba7a394f078fa5d7d14e146105757e34f` 的 Boolean
`mux` 实现包含两个 PBS。旧 benchmark 调用
`server.mux(&left, &right, &left)`，第二个 PBS 的输入掩码为零；新 harness
使用独立的 `when_false`，并在 JSON 中写入 `mux_input_mode: "distinct"`。
验证脚本拒绝缺少该标记的证据。

## 本机 latest MoonBit/native 结果

运行方式：

```text
moon test src/boolean/benchmark_driver_native_wbtest.mbt --target native \
  --include-skipped -i 0
moon test src/boolean/benchmark_driver_native_wbtest.mbt --target native \
  --include-skipped -i 1
cargo run --manifest-path tools/benchmark/tfhe-rs/Cargo.toml --release --locked \
  -- boolean-110 performance
cargo run --manifest-path tools/benchmark/tfhe-rs/Cargo.toml --release --locked \
  -- boolean-128 performance
```

| 参数 | MoonTFHE MUX | tfhe-rs MUX | 比率 | MoonTFHE 第 1 PBS | 第 2 PBS | 合并 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 110 | 60,248.386 us | 17,298.577 us | 3.48x | 30,003.328 us | 30,029.875 us | 18.273 us |
| 128 | 93,459.083 us | 26,933.789 us | 3.47x | 46,593.242 us | 46,571.217 us | 18.593 us |

同一批运行的 NAND 为 3.47x（110）和 3.63x（128）。因此 MUX 的额外开销
主要是第二次 PBS，而不是最终线性合并；把合并改写或重复构造 LUT 不能把通用
MUX 降到单 PBS。

## 已合入的安全优化

- 通用路径复用一次 half-amplitude NAND LUT。
- 第二分支直接计算 `when_false - selector`，不再物化 `!selector` 的完整 LWE
  密文。
- `when_true == when_false` 直接返回分支；`selector == when_true` 和
  `selector == when_false` 分别降为 OR/AND 的单 PBS 恒等式。
- 新增小参数真值测试覆盖三类恒等式和通用路径。

这些优化不会改变 `mux: 2` 的通用门契约。要进一步接近 tfhe-rs，需要在共享
Fourier key 的前提下实现双 PBS fused kernel 或并行 workspace；这属于 native
provider 层的下一阶段实验，不能用单输入 LUT 或分数 Torus 缩放替代。

上述数字是本机一次受控运行，不是远端 RC 证据；远端结果仍以带 runner 元数据
的 `boolean-rc-evidence` artifact 为准。
