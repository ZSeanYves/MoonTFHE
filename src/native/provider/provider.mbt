///|
pub suberror NativeProviderError {
  UnsupportedBackend
  InvalidLength
  InvalidPolynomialSize
  AuthenticationFailed
  ProviderFailure(status~ : Int)
} derive(Debug, Eq)

///|
/// Native handle backed by a MoonBit external object. The finalizer releases
/// the Rust plan and its caller-owned scratch storage.
type NativeFftPlan

///|
/// Native Fourier bootstrap key. Its Rust allocation is released by the
/// external-object finalizer.
type NativeFourierBootstrapKey

///|
/// Native one-call PBS context backed by a GC-managed external object.
type NativePbsContext

///|
/// Reusable FFT plan and workspace with validated capacities retained in
/// MoonBit.
pub struct FftPlan {
  handle : NativeFftPlan
  size : Int
  digit_capacity : Int
  output_capacity : Int
}

///|
/// Coefficient BSK converted to the provider's half-spectrum representation.
/// Retaining `plan` keeps its Rust plan and workspace alive for every call.
pub struct FourierBootstrapKey {
  handle : NativeFourierBootstrapKey
  plan : FftPlan
  ggsw_count : Int
  digit_count : Int
  output_count : Int
}

///|
/// Reusable native PBS evaluator. The handle owns the Fourier BSK, packed KSK,
/// FFT plan and all hot-path workspace; no secret key material is retained.
pub struct PbsContext {
  handle : NativePbsContext
  input_size : Int
  output_size : Int
  coefficient_count : Int
  ksk_count : Int
}

///|
pub struct PbsStageMetrics {
  key_switch_ns : Int64
  external_product_ns : Int64
  external_product_count : Int64
  blind_rotation_ns : Int64
  sample_extraction_ns : Int64
}

///|
pub fn PbsStageMetrics::key_switch_ns(self : PbsStageMetrics) -> Int64 {
  self.key_switch_ns
}

///|
pub fn PbsStageMetrics::external_product_ns(self : PbsStageMetrics) -> Int64 {
  self.external_product_ns
}

///|
pub fn PbsStageMetrics::external_product_count(self : PbsStageMetrics) -> Int64 {
  self.external_product_count
}

///|
pub fn PbsStageMetrics::blind_rotation_ns(self : PbsStageMetrics) -> Int64 {
  self.blind_rotation_ns
}

///|
pub fn PbsStageMetrics::sample_extraction_ns(self : PbsStageMetrics) -> Int64 {
  self.sample_extraction_ns
}

///|
fn decode_fft_status(status : Int) -> Result[Unit, NativeProviderError] {
  if status == 0 {
    Ok(())
  } else if status == 2 {
    Err(InvalidLength)
  } else {
    Err(ProviderFailure(status~))
  }
}

///|
fn decode_aead_result(raw : Bytes) -> Result[Bytes, NativeProviderError] {
  if raw.length() < 1 {
    return Err(ProviderFailure(status=-1))
  }
  let status = raw[0].to_int()
  if status == 0 {
    Ok(raw[1:].to_owned())
  } else if status == 2 {
    Err(AuthenticationFailed)
  } else {
    Err(ProviderFailure(status~))
  }
}
