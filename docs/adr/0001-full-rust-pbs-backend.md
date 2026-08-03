# ADR 0001: Move the Native PBS Hot Loop to Rust

- Status: Implemented
- Date: 2026-08-03
- Release impact: keep the current release research-only

## Context

O0-O3 preserved the original ownership boundary: MoonBit performs modulus
switching, accumulator rotation, signed decomposition, blind-rotation state
transitions, sample extraction and key switching; RustFFT performs Fourier
external products through a borrowed-array C ABI.

The approach is correct and memory-safe, but it does not meet the performance
gate. The same-runner O3 evidence in
`docs/performance/o3-fused-fourier.json` records:

| Parameter | PBS | NAND/tfhe-rs | Peak RSS |
|---|---:|---:|---:|
| boolean-110 | 322.4 ms | 25.59x | 463.4 MiB |
| boolean-128 | 458.6 ms | 24.70x | 530.1 MiB |

Fusing the external product and accumulator add improved the same EPYC 7763
runner over O2, but the result remains above the explicit 10x stop threshold.
The 128-bit process also remains above the 512 MiB stop threshold. Continuing
with gate rewrites or serialization changes cannot remove the per-control FFT
and language-boundary costs inside one PBS.

The resident ServerKey also retains coefficient and Fourier BSK
representations. With a `Complex64` half spectrum, the Fourier representation
uses twice the coefficient BSK bytes. Keeping both representations makes the
final 256/320 MiB RSS targets structurally unattainable after runtime and KSK
overhead are included.

## Decision

Implement a complete native PBS backend behind one stable C ABI call. MoonBit
continues to own public parameters, key lifecycle, ciphertext validation,
Boolean gate/LUT encoding and error mapping. Rust owns the native evaluation
context and the entire performance-critical PBS operation:

1. modulus switching;
2. accumulator initialization and rotations;
3. signed decomposition;
4. blind rotation and external products;
5. sample extraction;
6. key switching in the configured PBS order.

The release artifact must not link tfhe-rs. The pinned tfhe-rs commit remains a
dev-only fixture and benchmark oracle.

The initial C ABI is intentionally small:

```text
native_pbs_context_new(parameters, coefficient_bsk, ksk) -> handle
native_pbs_context_valid(handle) -> status
native_pbs_evaluate_lut(handle, input_lwe, accumulator, output_lwe) -> status
native_pbs_workspace_reset(handle) -> status
native_pbs_context_free(handle)
```

All MoonBit arrays are borrowed for the duration of a call. The Rust context is
an external object with one idempotent finalizer. Every length calculation is
checked before pointer conversion, Rust panics are caught at the ABI boundary,
and error codes are mapped to the existing structured evaluation errors.

The context owns a reusable workspace. After initialization, 1,000 consecutive
PBS calls must perform zero Rust heap allocations. Concurrent evaluation uses
one workspace per evaluator/thread; a single context must reject reentrant use
instead of racing mutable scratch.

## Memory Model

Native evaluation retains Fourier BSK, packed KSK, parameters and workspace.
It does not retain a second coefficient BSK after conversion. The portable
reference backend continues to retain coefficient data.

MBKS remains a backend-independent coefficient format. Native serialization
reconstructs coefficients from the Fourier representation on demand. This is
allowed only after full-width Torus32 roundtrip fixtures prove exact recovery
for N=512 and N=1024. If exact recovery cannot be proven, MBKS serialization
must require an explicit coefficient-backed ServerKey mode and that mode is
excluded from steady-state performance claims.

## Delivery Gates

1. Add standalone Rust stage benchmarks for decomposition, one external
   product, blind rotation, sample extraction, KSK apply and complete PBS.
2. Add coefficient/Fourier/coefficient exact roundtrip fixtures.
3. Add differential tests against the current MoonBit reference oracle for
   toy, 110-bit and 128-bit parameters.
4. Add malformed length, aliasing, reentrancy, repeated free and ASan tests.
5. Measure a one-call RustFFT implementation. It must reach at most 10x
   tfhe-rs before Boolean gate or serialization work resumes.
6. If RustFFT remains above 10x, replace only the Fourier kernel with a
   repository-owned permissively licensed specialized negacyclic FFT. Do not
   introduce concrete-fft or link tfhe-rs into the release.
7. Resume O4-O7 only after PBS and NAND are at most 10x and peak RSS is below
   512 MiB; RC still requires 5x and 256/320 MiB.

## Consequences

The native backend becomes a larger trusted implementation component, so its
Rust differential, fuzz, sanitizer and no-allocation coverage must grow. The
public MoonBit Boolean API does not change. Portable backends remain correct
reference implementations without a performance promise.

The continuation gate was passed by the one-call context, after which O4-O7
were completed. Final run `30803448754` records worst-case PBS/NAND at
4.216x/4.205x and peak RSS at 217,596/231,980 KiB. The engineering RC gate now
passes, while the project remains a research release pending independent audit.
