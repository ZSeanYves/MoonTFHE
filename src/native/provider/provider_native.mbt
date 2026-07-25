///|
pub fn fft_plan_new(size : Int) -> Result[FftPlan, NativeProviderError] {
  if size <= 0 || (size & (size - 1)) != 0 {
    return Err(InvalidPolynomialSize)
  }
  let handle = fft_plan_new_ffi(size)
  if fft_plan_valid_ffi(handle) {
    Ok({ handle, size })
  } else {
    Err(ProviderFailure(status=-1))
  }
}

///|
pub fn FftPlan::negacyclic_mul_u32_le(
  self : FftPlan,
  left : Bytes,
  right : Bytes,
) -> Result[Bytes, NativeProviderError] {
  if left.length() == 0 ||
    left.length() != right.length() ||
    left.length() != self.size * 4 {
    return Err(InvalidLength)
  }
  decode_fft_result(fft_plan_multiply_ffi(self.handle, left, right))
}

///|
pub fn aes256_gcm_encrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, NativeProviderError] {
  if key.length() != 32 || nonce.length() != 12 {
    return Err(InvalidLength)
  }
  decode_aead_result(aes256_gcm_encrypt_ffi(key, nonce, aad, plaintext))
}

///|
pub fn aes256_gcm_decrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_and_tag : Bytes,
) -> Result[Bytes, NativeProviderError] {
  if key.length() != 32 ||
    nonce.length() != 12 ||
    ciphertext_and_tag.length() < 16 {
    return Err(InvalidLength)
  }
  decode_aead_result(
    aes256_gcm_decrypt_ffi(key, nonce, aad, ciphertext_and_tag),
  )
}
