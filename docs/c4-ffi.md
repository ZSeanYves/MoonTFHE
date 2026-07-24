# C4 native providers

C4 adds two standalone, permissively licensed Rust providers. They are not
part of the MoonBit reference backend and do not change ciphertext encoding.

`native/fft` pins RustFFT to commit
`4758ab0dd6f256c50ac8987c75c9cb96152dc2ca` (RustFFT 6.4.1). Its C ABI accepts
`uint32_t` Torus32 coefficients and computes a negacyclic product modulo
`2^32`. The 16-bit limb split avoids converting a full Torus32 value to an
inexact `f64` value. `fft_plan_scratch_bytes` is part of the stable ABI and the
caller must provide a non-null scratch pointer for every product call.

`native/aead` pins `aes-gcm` 0.10.3 and exposes AES-256-GCM with a caller-
provided 32-byte key and 12-byte nonce. Authentication failures return one
status code and clear the destination buffer. Neither provider derives keys
from passwords, timestamps, or identifiers.

Both crates pin Rust 1.82.0, commit their `Cargo.lock`, and are tested by the
`rust-ffi` CI job with `cargo test --locked`. The MoonBit reference polynomial
backend remains the correctness baseline; wiring a native plan into PBS is a
separate C5/C6 integration task and is intentionally not implied by these
standalone ABI tests.
