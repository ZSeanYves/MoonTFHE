# P1 Behavioral Contract

This document is the replacement contract for the legacy package. It describes
observable behavior, not security claims.

## Torus32

Torus values are elements of `Z/(2^32)Z` represented by a wrapping MoonBit
`Int`. Addition and subtraction are modulo `2^32`. The symmetric Boolean
encoding is:

```text
true  -> +2^30
false -> -2^30
decode(x) = (x >= 0)
```

Power-of-two modulus switching uses nearest rounding:

```text
switch(x, q) = floor((unsigned(x) * q + 2^31) / 2^32) mod q
```

The P1 reference tests cover zero, quarter, half-minus-one, every small
plaintext modulus value, and negative torus representatives.

## Negacyclic ring

Polynomials use `Z/(X^N + 1)Z`. The reference multiplication computes each
coefficient directly:

```text
c[k] = sum(i <= k, a[i] * b[k-i])
     - sum(i > k,  a[i] * b[k-i+N])
```

The candidate implementation must match this result coefficient-by-coefficient.
Future FFT/NTT backends are not allowed to replace the reference test.

## Signed gadget decomposition

For base `B = 2^base_log`, each digit is centered in
`[-B/2, B/2)`. The carry rule is part of the contract: a raw digit in the
upper half is represented by `raw - B` and increments the next carry. The
P1 reference test checks digit bounds and recomposition modulo `2^32`.

## LWE sample extraction

Extracting coefficient `k` from a TRLWE ciphertext uses the negacyclic relation
`X^N = -1`; coefficients that cross the boundary are negated. The existing
round-trip tests at `k=0` and `k>0` pin this sign convention.

## Reference boundary

`oracle_wbtest.mbt` is intentionally outside the public contract. It is a
plaintext reference for regression tests and may inspect legacy secret fields.
No production implementation may import or call it. P3 will replace those
tests with secret-free blind-rotation vectors.
