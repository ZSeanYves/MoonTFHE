# R7 RC Evidence

R7 separates inexpensive pull-request checks from production evidence:

- `MoonTFHE CI` runs all-target contracts, four backend tests, Rust FFI/ASan
  and a low-cost polynomial benchmark smoke.
- `Boolean RC Evidence` is scheduled and dispatchable. It runs native 110/128
  MoonTFHE and the fixed tfhe-rs revision on the same runner, then executes the
  skipped 1,000-step circuit tests for both parameter sets.
- `tools/benchmark/collect.py` emits the only accepted benchmark schema.
  `tools/benchmark/check.py` recomputes ratios and rejects placeholders,
  inconsistent values and excess memory.
- `tools/rc-gate/check.sh` requires the immutable estimator, verified noise
  model, stable API/import surface, standard circuit tests, locked tfhe-rs
  harness, committed benchmark evidence and weighted score thresholds.

The latest measured artifact is committed as `docs/benchmarks-tfhe-rs.json`;
phase snapshots remain under `docs/performance/`, including the O1 artifact
`docs/performance/o1-packed-workspace.json`. The programmable-bootstrap
measurement uses a non-trivial NOT LUT so that it cannot be satisfied by an
identity-copy fast path. After separating release compilation from runtime
RSS, O1 records NAND at about 25.24x (110-bit) and 25.47x (128-bit) slower than
the pinned tfhe-rs harness, with peak RSS about 462.5 MiB and 529.1 MiB. The
release therefore remains research-only. These failures are optimization work
items, not reasons to weaken the gate.

The same workflow's standard-circuits job completed successfully for both
1,000-step random Boolean workloads after O3 (run `30789949471`). This
establishes the
correctness evidence gate, but does not change the performance or memory
requirements.

O3 fused the native Fourier external product and accumulator add without
moving decomposition or the blind-rotation state machine out of MoonBit. The
result remained 25.59x/24.70x slower than tfhe-rs, and 128-bit RSS remained
530.1 MiB. These measurements activate the optimization stop rule documented
in `docs/adr/0001-full-rust-pbs-backend.md`; O4-O7 and RC publication remain
paused until a one-call native PBS backend passes the 10x/512 MiB continuation
gate.
