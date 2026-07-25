# R4 128-bit and portable semantics

The 128-bit reference record now uses the same native construction and PBS
implementation as the 110-bit record. Only the typed dimensions,
decomposition records, and fixed Gaussian fixtures differ. There is no second
algorithm branch.

For `k=2`, `N=1024`, and LWE dimension 837, the canonical resident material is
approximately 52.96 MiB coefficient BSK, 32.74 MiB KSK, and 117.70 MiB Fourier
BSK, or 203.40 MiB total before small workspaces. This is below the 224 MiB R4
key-material target.

All four backends continue to share Torus32, signed decomposition, coefficient
layout, parameter IDs, KeyId encoding, CDT fixtures, and serialization scalar
contracts. Native executes both standard parameter sets. Portable targets
return structured `UnsupportedBackend` before key allocation when no host
entropy provider exists. With a provider they can construct and evaluate the
same coefficient keys through the intentional `O(N^2)` reference backend; that
path has no latency commitment and belongs in scheduled smoke rather than PR CI.

Neither parameter set loses `reference_only` status in R4. That transition is
reserved for the estimator and failure-rate gates.
