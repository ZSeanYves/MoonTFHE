# R2 production Fourier kernel

R2 replaces the byte-copying native FFT adapter with a borrowed, contiguous
`FixedArray[UInt]` ABI. MoonBit owns blind-rotation state, signed decomposition,
digit selection, and CMUX orchestration. Rust owns only Fourier conversion,
negacyclic convolution, indexed external products, and reusable workspaces.

## Representation

- A polynomial contains `N` Torus32 coefficients.
- A Fourier polynomial contains `N / 2` `Complex64` values. The omitted half is
  reconstructed by conjugate symmetry of the odd negacyclic roots.
- Full-width standalone Torus32 products are split into 16-bit limbs. The BSK
  cache instead uses one centered `Complex64` half-spectrum per polynomial,
  matching the memory model needed by standard TFHE bootstrapping.
- A Fourier BSK is indexed as
  `[ggsw][digit][output][frequency]`.

The coefficient BSK remains the canonical serialization form. The Fourier form
is an opaque native cache and is never part of the stable Boolean API.

## Ownership and allocation contract

`FftPlan` and `FourierBootstrapKey` wrap MoonBit external objects. Their C
finalizers release the Rust plan, scratch, and Fourier storage exactly once.
The MoonBit Fourier key retains its plan, so a plan cannot be finalized while a
key still uses its workspace.

Plan construction preallocates RustFFT scratch, digit spectra, convolution
limbs, output accumulation, and the inverse half-spectrum buffer. After BSK
conversion, `indexed_ggsw_external_product_u32` performs no heap allocation.
An integration test installs a counting allocator and checks 1,000 consecutive
calls.

All C ABI lengths are validated before creating Rust slices. Shape products use
checked arithmetic, errors return status codes, and Rust panics are caught at
the ABI boundary. MoonBit arrays are passed with `#borrow`; native code never
retains their addresses after a call.

## Verification boundary

Rust differential tests cover full-width Torus32 negacyclic products at
`N = 32`, `512`, and `1024`, plus indexed Fourier external products. MoonBit
tests exercise the same borrowed-array ABI. CI runs the Rust suite on pinned
Rust 1.82 and separately runs it under a pinned nightly AddressSanitizer build.

R2 does not claim a production Boolean PBS. R3 must stream a real 110-bit
coefficient BSK into this cache and pass the memory and end-to-end PBS gates.
