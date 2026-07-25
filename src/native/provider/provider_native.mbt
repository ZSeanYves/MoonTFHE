///|
pub fn fft_plan_new(size : Int) -> Result[FftPlan, NativeProviderError] {
  fft_plan_new_with_capacity(size, 1, 1)
}

///|
pub fn fft_plan_new_with_capacity(
  size : Int,
  digit_capacity : Int,
  output_capacity : Int,
) -> Result[FftPlan, NativeProviderError] {
  if size <= 0 || (size & (size - 1)) != 0 {
    return Err(InvalidPolynomialSize)
  }
  if digit_capacity <= 0 || output_capacity <= 0 {
    return Err(InvalidLength)
  }
  let handle = fft_plan_new_ffi(size, digit_capacity, output_capacity)
  if fft_plan_valid_ffi(handle) {
    Ok({ handle, size, digit_capacity, output_capacity })
  } else {
    Err(ProviderFailure(status=-1))
  }
}

///|
pub fn FftPlan::negacyclic_mul_u32(
  self : FftPlan,
  left : FixedArray[UInt],
  right : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  if left.length() == 0 ||
    left.length() != right.length() ||
    left.length() != output.length() ||
    left.length() != self.size {
    return Err(InvalidLength)
  }
  decode_fft_status(fft_plan_multiply_ffi(self.handle, left, right, output))
}

///|
pub fn FftPlan::batched_glwe_convolution(
  self : FftPlan,
  left : FixedArray[UInt],
  right : FixedArray[UInt],
  term_count : Int,
  output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  if term_count <= 0 ||
    left.length() % self.size != 0 ||
    left.length() / self.size != term_count ||
    right.length() != left.length() ||
    output.length() != self.size {
    return Err(InvalidLength)
  }
  decode_fft_status(
    fft_plan_batched_convolution_ffi(
      self.handle,
      left,
      right,
      term_count,
      output,
    ),
  )
}

///|
pub fn fourier_bsk_new(
  plan : FftPlan,
  coefficients : FixedArray[UInt],
  ggsw_count : Int,
  digit_count : Int,
  output_count : Int,
) -> Result[FourierBootstrapKey, NativeProviderError] {
  if ggsw_count <= 0 ||
    digit_count <= 0 ||
    output_count <= 0 ||
    digit_count > plan.digit_capacity ||
    output_count > plan.output_capacity ||
    coefficients.length() % plan.size != 0 ||
    coefficients.length() / plan.size % output_count != 0 ||
    coefficients.length() / plan.size / output_count % digit_count != 0 ||
    coefficients.length() / plan.size / output_count / digit_count != ggsw_count {
    return Err(InvalidLength)
  }
  let handle = fourier_bsk_new_ffi(
    plan.handle,
    coefficients,
    ggsw_count,
    digit_count,
    output_count,
  )
  if fourier_bsk_valid_ffi(handle) {
    Ok({ handle, plan, ggsw_count, digit_count, output_count })
  } else {
    Err(ProviderFailure(status=-1))
  }
}

///|
pub fn FourierBootstrapKey::external_product(
  self : FourierBootstrapKey,
  ggsw_index : Int,
  digits : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  if ggsw_index < 0 ||
    ggsw_index >= self.ggsw_count ||
    digits.length() % self.plan.size != 0 ||
    digits.length() / self.plan.size != self.digit_count ||
    output.length() % self.plan.size != 0 ||
    output.length() / self.plan.size != self.output_count {
    return Err(InvalidLength)
  }
  decode_fft_status(
    fourier_bsk_external_product_ffi(
      self.plan.handle,
      self.handle,
      ggsw_index,
      digits,
      output,
    ),
  )
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
