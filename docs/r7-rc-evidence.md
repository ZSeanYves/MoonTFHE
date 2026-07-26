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

The measured artifact is committed as `docs/benchmarks-tfhe-rs.json`. The
programmable-bootstrap measurement uses a non-trivial NOT LUT so that it
cannot be satisfied by an identity-copy fast path. On the recorded runner,
MoonTFHE NAND is about 30.25x (110-bit) and 30.24x (128-bit) slower than the
pinned tfhe-rs harness; peak RSS is about 4.29 GiB and 530 MiB respectively,
above the RC limits. The release therefore remains research-only. These
failures are optimization work items, not reasons to weaken the gate.

The same workflow's standard-circuits job completed successfully for both
1,000-step random Boolean workloads (run `30191924719`). This establishes the
correctness evidence gate, but does not change the performance or memory
requirements.
