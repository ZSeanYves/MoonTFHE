///|
pub fn fft_plan_new(_size : Int) -> Result[FftPlan, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn fft_plan_new_with_capacity(
  _size : Int,
  _digit_capacity : Int,
  _output_capacity : Int,
) -> Result[FftPlan, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn FftPlan::negacyclic_mul_u32(
  _self : FftPlan,
  _left : FixedArray[UInt],
  _right : FixedArray[UInt],
  _output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn FftPlan::batched_glwe_convolution(
  _self : FftPlan,
  _left : FixedArray[UInt],
  _right : FixedArray[UInt],
  _term_count : Int,
  _output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn fourier_bsk_new(
  _plan : FftPlan,
  _coefficients : FixedArray[UInt],
  _ggsw_count : Int,
  _digit_count : Int,
  _output_count : Int,
) -> Result[FourierBootstrapKey, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn FourierBootstrapKey::external_product(
  _self : FourierBootstrapKey,
  _ggsw_index : Int,
  _digits : FixedArray[UInt],
  _output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn aes256_gcm_encrypt(
  _key : Bytes,
  _nonce : Bytes,
  _aad : Bytes,
  _plaintext : Bytes,
) -> Result[Bytes, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn aes256_gcm_decrypt(
  _key : Bytes,
  _nonce : Bytes,
  _aad : Bytes,
  _ciphertext_and_tag : Bytes,
) -> Result[Bytes, NativeProviderError] {
  Err(UnsupportedBackend)
}
