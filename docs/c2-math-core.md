# C2 typed mathematical core

C2 makes the maintained core's torus and shape contracts explicit:

- `Torus32` stores a `UInt` and all arithmetic wraps modulo `2^32` without
  relying on host `Int` overflow behavior;
- typed LWE keys/ciphertexts use `LweDimension`, Torus32 coefficients, and
  structured dimension/noise errors;
- GLWE sample extraction checks the coefficient index and applies the
  negacyclic sign rule for every GLWE component;
- GGSW shape is `(k + 1) * level` rows by `k + 1` GLWE columns;
- signed gadget decomposition and recomposition are available as a
  differential-testable keyswitch contract.

The current `src/boolean` facade still delegates to the deprecated root PBS
implementation. That dependency is intentionally removed only after C3 has a
production BSK/PBS path; the new core packages do not import the root package.
