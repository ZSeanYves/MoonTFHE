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
/// Reusable FFT plan with its validated polynomial size retained in MoonBit.
pub struct FftPlan {
  handle : NativeFftPlan
  size : Int
}

///|
fn decode_fft_result(raw : Bytes) -> Result[Bytes, NativeProviderError] {
  if raw.length() < 1 {
    return Err(ProviderFailure(status=-1))
  }
  let status = raw[0].to_int()
  if status == 0 {
    Ok(raw[1:].to_owned())
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
