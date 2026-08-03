# Boolean Core O7 audit

Audit date: 2026-08-03. The audited implementation is commit `28f762c`, with
same-runner performance and circuit evidence from GitHub Actions run
`30803448754`. The Boolean Core technical RC gate passes at **88/100**. The
project remains a research release until an independent cryptographic and
side-channel audit is completed.

## Hard gates

| Gate | Result | Evidence |
|---|---:|---|
| No legacy production randomness/noise | Pass | `tools/security-audit/check.sh` rejects SplitMix64, CLT, Box-Muller, floating Gaussian APIs and production panic paths. |
| Reproducible 110/128 parameter estimates | Pass with stated model limit | Immutable OCI digest and lattice-estimator commit are pinned; inputs, fixed-point noise fixtures and outputs are hash checked. The GLWE result is a documented flattened-LWE approximation, not an independent ring-security proof. |
| Standard PBS, gates and random circuits | Pass | Native 110/128 keygen, direct Boolean LUT PBS and 1,000-step chained random circuits pass for both parameter sets. |
| Secret-free ServerKey and serialization | Pass | MBKS v2 stores coefficient BSK/KSK only; Fourier state is rebuilt. MTSK v2 is explicit AES-256-GCM secret export/import. |
| Four backends, FFI, ASan and benchmark CI | Pass | MoonTFHE CI run `30803149677` and RC evidence run `30803448754` are green. |
| Performance and memory | Pass | Worst PBS/NAND ratios are 4.216x/4.205x. Peak RSS is 217,596/231,980 KiB for 110/128, below 256/320 MiB. Native steady-state PBS performs zero heap allocations. |

## Weighted score

| Area | Score | Basis |
|---|---:|---|
| Correctness | 31/35 | Typed Torus/LWE/GLWE/GGSW/KSK, standard native PBS, all Boolean gates, serialization round trips and both 1,000-step chained circuit suites pass. Points remain reserved for broader external vectors and independent review. |
| Security foundations | 22/25 | Secure entropy and domain-separated RFC8439 streams, fixed-point CDT noise, estimator/noise bounds, secret-free server boundary and authenticated secret export are verified. No independent cryptographic or side-channel audit exists. |
| Boolean API | 14/15 | Opaque stable facade, direct LUT gates, full key/ciphertext import/export and structured rejection paths are present. Portable standard execution remains reference-only. |
| Performance | 12/15 | PBS and NAND are within 5x of the pinned tfhe-rs Boolean gate harness; memory and zero-allocation gates pass. The implementation is not within 2x. |
| Tests/docs/maintenance | 9/10 | Four-backend CI, Rust FFI/ASan, immutable estimator, circuit evidence, benchmark regression schema and security audit are maintained. Independent audit artifacts are absent. |
| Total | **88/100** | Meets every numerical RC threshold. |

## Residual limits

- This score is an engineering maturity score for the Boolean Core, not a
  claim of audited production security.
- The estimator's GLWE number uses the recorded flattened-LWE approximation.
- JS/wasm/wasm-gc preserve layout and reference semantics but carry no
  performance commitment and require a trusted host entropy adapter.
- Shortint, Integer, GPU, C API interoperability and tfhe-rs ciphertext
  interoperability remain out of scope.
