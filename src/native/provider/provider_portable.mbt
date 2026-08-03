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
pub fn FourierBootstrapKey::external_product_batch(
  _self : FourierBootstrapKey,
  _ggsw_indices : FixedArray[UInt],
  _digits : FixedArray[UInt],
  _output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn FourierBootstrapKey::blind_rotation_step(
  _self : FourierBootstrapKey,
  _ggsw_index : Int,
  _digits : FixedArray[UInt],
  _addend : FixedArray[UInt],
  _output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn fourier_accumulator_add_in_place(
  _accumulator : FixedArray[UInt],
  _addend : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn FftPlan::workspace_reset(
  _self : FftPlan,
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn pbs_context_new(
  _polynomial_size : Int,
  _input_dimension : Int,
  _glwe_dimension : Int,
  _pbs_base_log : Int,
  _pbs_level : Int,
  _ksk_input_dimension : Int,
  _ksk_output_dimension : Int,
  _ksk_base_log : Int,
  _ksk_level : Int,
  _order : Int,
  _coefficients : FixedArray[UInt],
  _ksk : FixedArray[UInt],
) -> Result[PbsContext, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn pbs_context_new_empty(
  _polynomial_size : Int,
  _input_dimension : Int,
  _glwe_dimension : Int,
  _pbs_base_log : Int,
  _pbs_level : Int,
  _ksk_input_dimension : Int,
  _ksk_output_dimension : Int,
  _ksk_base_log : Int,
  _ksk_level : Int,
  _order : Int,
  _ksk : FixedArray[UInt],
) -> Result[PbsContext, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn PbsContext::set_control(
  _self : PbsContext,
  _index : Int,
  _coefficients : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn PbsContext::is_ready(_self : PbsContext) -> Bool {
  false
}

///|
pub fn PbsContext::evaluate_lut_into(
  _self : PbsContext,
  _input : FixedArray[UInt],
  _accumulator : FixedArray[UInt],
  _output : FixedArray[UInt],
) -> Result[Unit, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn PbsContext::export_coefficients(
  _self : PbsContext,
) -> Result[FixedArray[UInt], NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn PbsContext::export_ksk(
  _self : PbsContext,
) -> Result[FixedArray[UInt], NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn PbsContext::resident_bytes(_self : PbsContext) -> Int64 {
  0L
}

///|
pub fn PbsContext::memory_metrics(_self : PbsContext) -> PbsMemoryMetrics {
  {
    tracked_resident_bytes: 0L,
    coefficient_bsk_bytes: 0L,
    fourier_bsk_bytes: 0L,
    ksk_bytes: 0L,
    workspace_bytes: 0L,
  }
}

///|
pub fn PbsContext::measure_kernel_allocations(
  _self : PbsContext,
  _input : FixedArray[UInt],
  _accumulator : FixedArray[UInt],
  _output : FixedArray[UInt],
  _iterations : Int,
) -> Result[Int64, NativeProviderError] {
  Err(UnsupportedBackend)
}

///|
pub fn PbsContext::stage_metrics(_self : PbsContext) -> PbsStageMetrics {
  {
    key_switch_ns: 0L,
    external_product_ns: 0L,
    external_product_count: 0L,
    blind_rotation_ns: 0L,
    sample_extraction_ns: 0L,
  }
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
