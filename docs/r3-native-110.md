# R3 native 110-bit vertical slice

R3 connects `generate_keys(boolean_110_parameters())` to native OS entropy,
the quantized standard Gaussian fixtures, contiguous coefficient keys, and the
R2 Fourier provider. The parameter record remains `reference_only`; this is an
implementation milestone, not a security claim.

## Data flow

Key generation creates independent ChaCha20 streams for key material, client
encryption masks, client encryption noise, bootstrap material, and
serialization nonces. It then generates:

1. an 805-dimensional binary input LWE key;
2. a `k=3`, `N=512` binary GLWE key;
3. a `1536 -> 805` LWE KSK with base log 3 and 5 levels;
4. 805 encrypted GGSW controls with base log 10 and 2 levels;
5. one centered `Complex64` half-spectrum Fourier cache.

GLWE masks and Gaussian samples stay in MoonBit. A reusable RustFFT plan only
computes the three batched mask/secret negacyclic convolutions for each GLWE
row. The server key stores no input or GLWE secret bits.

During PBS, MoonBit performs modulus switching, rotation, subtraction, signed
decomposition, CMUX state updates, sample extraction, and key switching. The
native provider receives only an encrypted GGSW index, a flat signed-digit
buffer, and caller-owned output storage.

## Memory budget

The canonical sizes for the fixed 110-bit record are:

| Material | Count | Size |
|---|---:|---:|
| coefficient BSK | `805 * 8 * 4 * 512` Torus32 | 50.31 MiB |
| KSK | `1536 * 5 * 806` Torus32 | 23.61 MiB |
| Fourier BSK | `805 * 8 * 4 * 256` Complex64 | 100.62 MiB |
| total evaluation material | | 174.54 MiB |

The FFT plan and reusable scratch are small relative to the keys. Keygen keeps
only one temporary GGSW object outside these canonical buffers, so the design
fits the R3 192 MiB steady-state and 256 MiB construction targets before
allocator/runtime overhead. CI smoke validates actual key generation and NAND;
R7 records runner RSS with the benchmark harness.

## Remaining gates

R4 must reuse the same path for the 128-bit record and run the larger circuit
matrix. R5 must serialize the coefficient BSK and KSK, rebuilding the Fourier
cache after import. R6 must replace `reference_only` with estimator evidence.
