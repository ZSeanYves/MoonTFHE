# Performance Baseline

P5 keeps correctness and performance measurements separate. The current
benchmarks are native-only smoke measurements for the two dominant legacy
paths:

```bash
moon bench --target native --release --no-parallelize
```

The polynomial path is the `O(N^2)` negacyclic reference implementation. The
external-product benchmark includes allocation and naive polynomial products;
it is representative of the current research code, not a TFHE-rs comparison.

Before adding an FFT/NTT backend, record the output of the command above with
the MoonBit toolchain version and CPU model. Any optimized backend must match
the reference multiplication coefficient-for-coefficient and publish separate
measurements for key generation, external product, blind rotation, PBS, and
Boolean gate throughput.

## Baseline (2026-07-24)

- Host: `arm64`, Apple M4 (`Mac16,12`)
- Toolchain: `moon 0.1.20260713` (`moonc 0.10.4`)

```
[ZSeanYves/MoonTFHE] bench src/benchmarks.mbt:2 ("bench polynomial negacyclic n=128") ok
time (mean ± σ)         range (min … max)
   9.82 µs ± 537.64 ns     9.49 µs …  10.93 µs  in 10 ×  10471 runs
[ZSeanYves/MoonTFHE] bench src/benchmarks.mbt:9 ("bench TRGSW external product n=32") ok
time (mean ± σ)         range (min … max)
 100.98 µs ± 342.20 ns   100.45 µs … 101.41 µs  in 10 ×    997 runs
Total tests: 2, passed: 2, failed: 0.
```

These values are a local reference only; they are not a TFHE-rs performance claim.

The native provider now uses RustFFT 6.4.1 through a fixed C ABI. Torus32
coefficients are split into 16-bit limbs, the plan owns reusable scratch, and
full-width products are checked coefficient-by-coefficient against the MoonBit
reference backend in native CI. The R2 provider also stores BSK polynomials as
negacyclic half spectra and applies indexed GGSW external products with a
preallocated workspace.

## RC evidence harness

R7 adds native 110/128 key generation, programmable-bootstrap and NAND
measurements plus a dev-only tfhe-rs harness pinned to commit
`640911eba7a394f078fa5d7d14e146105757e34f`. The `Boolean RC Evidence`
workflow runs each parameter on the same `ubuntu-24.04` runner, records peak
RSS with `/usr/bin/time -v`, and uploads raw logs, the generated Cargo lockfile
and a structured comparison artifact.

The comparison artifact is accepted only after
`tools/benchmark/check.py --require-rc-performance` verifies real positive
measurements, 110/128 memory ceilings and the 5x NAND gate. Until that artifact
and its Cargo lockfile are committed, `tools/rc-gate/check.sh` intentionally
blocks RC publication.
