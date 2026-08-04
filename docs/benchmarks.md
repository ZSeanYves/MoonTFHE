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
`tools/benchmark/check.py --require-rc-performance` verifies schema-v3 evidence:
seven measured gate batches, ten key-generation samples, real serialized sizes,
a 1,000-call native allocator counter, zero steady-state PBS allocations, and
the 2x PBS/NAND/key-generation release gates. The O1 packed-workspace evidence is committed as
`docs/performance/o1-packed-workspace.json`. The workflow prebuilds the native
test harness before `/usr/bin/time` starts, so peak RSS measures the benchmark
process rather than the first release compilation. O1 reduced PBS to about
277.7/407.3 ms and NAND to about 279.3/413.7 ms for 110/128-bit parameters.
NAND remains 25.24x/25.47x slower than tfhe-rs and peak RSS is about
462.5/529.1 MiB, so the release still fails the final performance and memory
ceilings. The PBS field measures a non-trivial NOT LUT and is therefore a real
PBS datapoint.

The A4 evidence adds `external_product_count` to the stage metrics and records
the fixed Boolean PBS contract (`NAND`, `AND`, `OR`, `XOR`, and `XNOR` use one
PBS; `MUX` uses two). `tools/benchmark/profile_report.py` consumes the
collected schema-v3 artifact and reports stage fractions plus the measured
external-product total. This keeps optimization decisions tied to measured
rotation, Fourier product, extraction, and key-switch costs rather than to a
single aggregate NAND number. The optimized native rotation kernel uses
division-free split ranges and is covered by a full-wrap differential test;
the local 110-bit smoke measured roughly 30.3 ms PBS after the change. This is
an improvement, but it remains well above the 2x release target and does not
change the research-release status.

The O2 streaming-keygen evidence is committed as
`docs/performance/o2-streaming-keygen.json`. It records key generation at about
4.17x/4.08x tfhe-rs and peak RSS at about 463.6/530.1 MiB. The O1 and O2 runs
landed on different EPYC models, so their absolute gate times are not treated
as a code regression; each artifact remains internally same-runner and
interleaved. O2 confirms that temporary GGSW/KSK objects were not the dominant
steady-state memory cost. The coefficient and Fourier bootstrap-key
representations must not both remain resident in the optimized runtime.

The O3 fused-Fourier artifact is
`docs/performance/o3-fused-fourier.json`. On the same EPYC 7763 model used by
O2, fusing external product and accumulator addition reduced PBS to about
322.4/458.6 ms and NAND to 25.59x/24.70x tfhe-rs. Peak RSS remained about
463.4/530.1 MiB. This triggers the plan's `>10x` and `>512 MiB` stop rule.
This result activated the full-context alternative described by
`docs/adr/0001-full-rust-pbs-backend.md`. Streaming Fourier controls and moving
one complete PBS evaluation into the reusable native context removed the
coefficient/Fourier overlap and repeated MoonBit/FFI transitions. O4 then
lowered every binary gate to one direct LUT PBS (MUX uses two; NOT uses none).

## Previous evidence

The final artifact is `docs/benchmarks-tfhe-rs.json`, generated for commit
`28f762c` by workflow run `30803448754`:

| Parameter | PBS ratio | NAND ratio | Peak RSS |
|---|---:|---:|---:|
| Boolean 110 | 4.125x | 4.095x | 217,596 KiB |
| Boolean 128 | 4.216x | 4.205x | 231,980 KiB |

This pre-A0 artifact used the former ten-iteration protocol and is retained as
historical context only. It is not accepted by the schema-v3 checker or the
current RC gate. A fresh same-runner artifact must be generated by the evidence
workflow before any performance score is treated as current.
