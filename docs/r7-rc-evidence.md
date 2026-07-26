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

The current release remains a research release until the workflow artifact is
reviewed and committed. A failed 5x performance comparison is evidence to
optimize the implementation, not a reason to weaken the gate.
