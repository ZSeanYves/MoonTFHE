# O7 RC evidence

The final evidence is tied to commit `28f762c` and GitHub Actions run
`30803448754`. MoonTFHE and tfhe-rs commit
`640911eba7a394f078fa5d7d14e146105757e34f` ran interleaved on the same
`ubuntu-24.04` runner. The committed structured artifact is
`docs/benchmarks-tfhe-rs.json` and is independently recomputed by
`tools/benchmark/check.py --require-rc-performance`.

| Parameter | PBS | NAND | Peak RSS | Native workspace |
|---|---:|---:|---:|---:|
| Boolean 110 | 58.051 ms / 4.125x | 57.628 ms / 4.095x | 217,596 KiB | 130,338,777 bytes |
| Boolean 128 | 87.167 ms / 4.216x | 86.955 ms / 4.205x | 231,980 KiB | 157,839,481 bytes |

The native provider reports zero steady-state PBS heap allocations. The same
artifact contains independent measurements for key generation, KSK generation
and application, coefficient BSK generation, Fourier conversion, polynomial
multiplication, external product, blind rotation, sample extraction, PBS with
and without key switching, every one-PBS gate and two-PBS MUX. tfhe-rs does not
expose stable internal stage timers, so ratios are computed only where both
harnesses expose comparable values. Standalone MoonTFHE PBS is compared with
tfhe-rs Boolean NAND because that public operation evaluates one bootstrapped
gate.

The workflow's standard-circuits job also generated fresh 110/128 keys and
passed 1,000 chained random Boolean operations for each parameter set. Main CI
run `30803149677` separately passed all four MoonBit targets, Rust FFI tests,
the 1,000-call no-allocation tests and AddressSanitizer.

The engineering RC gate passes. Distribution remains research-only pending an
independent cryptographic and side-channel audit.
