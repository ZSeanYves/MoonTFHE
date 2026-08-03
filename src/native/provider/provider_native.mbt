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
pub fn FourierBootstrapKey::external_product_batch(
  self : FourierBootstrapKey,
  ggsw_indices : FixedArray[UInt],
  digits : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  let batch_count = ggsw_indices.length()
  let digits_per_batch = self.digit_count * self.plan.size
  let output_per_batch = self.output_count * self.plan.size
  if batch_count <= 0 ||
    digits_per_batch <= 0 ||
    output_per_batch <= 0 ||
    batch_count > 2_000_000_000 / digits_per_batch ||
    batch_count > 2_000_000_000 / output_per_batch ||
    digits.length() != batch_count * digits_per_batch ||
    output.length() != batch_count * output_per_batch {
    return Err(InvalidLength)
  }
  for index in 0..<batch_count {
    if ggsw_indices[index].reinterpret_as_int() < 0 ||
      ggsw_indices[index].reinterpret_as_int() >= self.ggsw_count {
      return Err(InvalidLength)
    }
  }
  decode_fft_status(
    fourier_bsk_external_product_batch_ffi(
      self.plan.handle,
      self.handle,
      ggsw_indices,
      digits,
      output,
    ),
  )
}

///|
/// Fused external product and accumulator add for one blind-rotation step.
pub fn FourierBootstrapKey::blind_rotation_step(
  self : FourierBootstrapKey,
  ggsw_index : Int,
  digits : FixedArray[UInt],
  addend : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  if ggsw_index < 0 ||
    ggsw_index >= self.ggsw_count ||
    digits.length() != self.digit_count * self.plan.size ||
    addend.length() != self.output_count * self.plan.size ||
    output.length() != addend.length() {
    return Err(InvalidLength)
  }
  decode_fft_status(
    fourier_blind_rotation_step_ffi(
      self.plan.handle,
      self.handle,
      ggsw_index,
      digits,
      addend,
      output,
    ),
  )
}

///|
pub fn fourier_accumulator_add_in_place(
  accumulator : FixedArray[UInt],
  addend : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  if accumulator.length() != addend.length() {
    return Err(InvalidLength)
  }
  decode_fft_status(fourier_accumulator_add_in_place_ffi(accumulator, addend))
}

///|
pub fn FftPlan::workspace_reset(
  self : FftPlan,
) -> Result[Unit, NativeProviderError] {
  decode_fft_status(fourier_workspace_reset_ffi(self.handle))
}

///|
pub fn pbs_context_new(
  polynomial_size : Int,
  input_dimension : Int,
  glwe_dimension : Int,
  pbs_base_log : Int,
  pbs_level : Int,
  ksk_input_dimension : Int,
  ksk_output_dimension : Int,
  ksk_base_log : Int,
  ksk_level : Int,
  order : Int,
  coefficients : FixedArray[UInt],
  ksk : FixedArray[UInt],
) -> Result[PbsContext, NativeProviderError] {
  if polynomial_size <= 0 ||
    (polynomial_size & (polynomial_size - 1)) != 0 ||
    input_dimension <= 0 ||
    glwe_dimension <= 0 ||
    pbs_base_log <= 0 ||
    pbs_level <= 0 ||
    pbs_base_log * pbs_level > 32 ||
    ksk_input_dimension <= 0 ||
    ksk_output_dimension <= 0 ||
    ksk_base_log <= 0 ||
    ksk_level <= 0 ||
    ksk_base_log * ksk_level > 32 ||
    order < 0 ||
    order > 1 {
    return Err(InvalidLength)
  }
  let columns = glwe_dimension + 1
  let digit_count = pbs_level * columns
  if digit_count <= 0 ||
    input_dimension > 2_000_000_000 / digit_count ||
    input_dimension * digit_count > 2_000_000_000 / columns ||
    input_dimension * digit_count * columns > 2_000_000_000 / polynomial_size {
    return Err(InvalidLength)
  }
  let coefficient_count = input_dimension *
    digit_count *
    columns *
    polynomial_size
  if ksk_input_dimension > 2_000_000_000 / ksk_level ||
    ksk_input_dimension * ksk_level > 2_000_000_000 / (ksk_output_dimension + 1) {
    return Err(InvalidLength)
  }
  let ksk_count = ksk_input_dimension * ksk_level * (ksk_output_dimension + 1)
  if coefficients.length() != coefficient_count || ksk.length() != ksk_count {
    return Err(InvalidLength)
  }
  let handle = pbs_context_new_ffi(
    polynomial_size, input_dimension, glwe_dimension, pbs_base_log, pbs_level, ksk_input_dimension,
    ksk_output_dimension, ksk_base_log, ksk_level, order, coefficients, ksk,
  )
  if !pbs_context_valid_ffi(handle) {
    return Err(ProviderFailure(status=-1))
  }
  Ok({
    handle,
    input_size: if order == 0 {
      ksk_input_dimension + 1
    } else {
      input_dimension + 1
    },
    output_size: if order == 0 {
      ksk_input_dimension + 1
    } else {
      ksk_output_dimension + 1
    },
    coefficient_count,
    ksk_count,
  })
}

///|
pub fn pbs_context_new_empty(
  polynomial_size : Int,
  input_dimension : Int,
  glwe_dimension : Int,
  pbs_base_log : Int,
  pbs_level : Int,
  ksk_input_dimension : Int,
  ksk_output_dimension : Int,
  ksk_base_log : Int,
  ksk_level : Int,
  order : Int,
  ksk : FixedArray[UInt],
) -> Result[PbsContext, NativeProviderError] {
  if polynomial_size <= 0 ||
    (polynomial_size & (polynomial_size - 1)) != 0 ||
    input_dimension <= 0 ||
    glwe_dimension <= 0 ||
    pbs_base_log <= 0 ||
    pbs_level <= 0 ||
    pbs_base_log * pbs_level > 32 ||
    ksk_input_dimension <= 0 ||
    ksk_output_dimension <= 0 ||
    ksk_base_log <= 0 ||
    ksk_level <= 0 ||
    ksk_base_log * ksk_level > 32 ||
    order < 0 ||
    order > 1 ||
    ksk_input_dimension > 2_000_000_000 / ksk_level ||
    ksk_input_dimension * ksk_level > 2_000_000_000 / (ksk_output_dimension + 1) {
    return Err(InvalidLength)
  }
  let columns = glwe_dimension + 1
  let digit_count = pbs_level * columns
  if digit_count <= 0 ||
    input_dimension > 2_000_000_000 / digit_count ||
    input_dimension * digit_count > 2_000_000_000 / columns ||
    input_dimension * digit_count * columns > 2_000_000_000 / polynomial_size {
    return Err(InvalidLength)
  }
  let coefficient_count = input_dimension *
    digit_count *
    columns *
    polynomial_size
  let ksk_count = ksk_input_dimension * ksk_level * (ksk_output_dimension + 1)
  if ksk.length() != ksk_count {
    return Err(InvalidLength)
  }
  let handle = pbs_context_new_empty_ffi(
    polynomial_size, input_dimension, glwe_dimension, pbs_base_log, pbs_level, ksk_input_dimension,
    ksk_output_dimension, ksk_base_log, ksk_level, order, ksk,
  )
  if !pbs_context_valid_ffi(handle) {
    return Err(ProviderFailure(status=-1))
  }
  Ok({
    handle,
    input_size: if order == 0 {
      ksk_input_dimension + 1
    } else {
      input_dimension + 1
    },
    output_size: if order == 0 {
      ksk_input_dimension + 1
    } else {
      ksk_output_dimension + 1
    },
    coefficient_count,
    ksk_count,
  })
}

///|
pub fn PbsContext::set_control(
  self : PbsContext,
  index : Int,
  coefficients : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  decode_fft_status(
    pbs_context_set_control_ffi(self.handle, index, coefficients),
  )
}

///|
pub fn PbsContext::is_ready(self : PbsContext) -> Bool {
  pbs_context_ready_ffi(self.handle)
}

///|
pub fn PbsContext::evaluate_lut_into(
  self : PbsContext,
  input : FixedArray[UInt],
  accumulator : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  if input.length() != self.input_size || output.length() != self.output_size {
    return Err(InvalidLength)
  }
  decode_fft_status(
    pbs_evaluate_lut_ffi(self.handle, input, accumulator, output),
  )
}

///|
pub fn PbsContext::export_coefficients(
  self : PbsContext,
) -> Result[FixedArray[UInt], NativeProviderError] {
  let output = FixedArray::make(self.coefficient_count, 0U)
  match
    decode_fft_status(pbs_context_export_coefficients_ffi(self.handle, output)) {
    Ok(_) => Ok(output)
    Err(error) => Err(error)
  }
}

///|
pub fn PbsContext::export_ksk(
  self : PbsContext,
) -> Result[FixedArray[UInt], NativeProviderError] {
  let output = FixedArray::make(self.ksk_count, 0U)
  match decode_fft_status(pbs_context_export_ksk_ffi(self.handle, output)) {
    Ok(_) => Ok(output)
    Err(error) => Err(error)
  }
}

///|
pub fn PbsContext::resident_bytes(self : PbsContext) -> Int64 {
  pbs_context_resident_bytes_ffi(self.handle)
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
