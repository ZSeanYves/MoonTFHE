///|
pub fn fft_plan_new(_size : Int) -> Result[FftPlan, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn FftPlan::negacyclic_mul_u32_le(
  _self : FftPlan,
  _left : Bytes,
  _right : Bytes,
) -> Result[Bytes, NativeProviderError] {
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
