///|
#warnings("-unused_field")
priv struct StandardKeygenStageMetrics {
  ksk_generation_us : Double
  bsk_coefficient_generation_us : Double
  bsk_fourier_conversion_us : Double
}

///|
let last_standard_keygen_stage_metrics : Ref[StandardKeygenStageMetrics] = @ref.new({
    ksk_generation_us: 0.0,
    bsk_coefficient_generation_us: 0.0,
    bsk_fourier_conversion_us: 0.0,
  },
)

///|
#warnings("-unused_value")
fn standard_keygen_stage_metrics() -> StandardKeygenStageMetrics {
  last_standard_keygen_stage_metrics.val
}

///|
fn generate_standard_keys_impl(
  parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  let security_bits = parameters.security.target_security_bits()
  if security_bits != 110 && security_bits != 128 {
    return Err(UnsupportedBackend)
  }
  let key_rng = match
    @random.secure_rng_new_for(@random.key_generation_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let mask_rng = match @random.secure_encryption_mask_rng_new() {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let noise_rng = match @random.secure_encryption_noise_rng_new() {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let bsk_rng = match
    @random.secure_rng_new_for(@random.bootstrap_key_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let serialization_rng = match
    @random.secure_rng_new_for(@random.serialization_nonce_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let input_dimension = parameters.record.lwe_dimension()
  let input_bits = Array::makei(input_dimension.value(), fn(_) {
    (key_rng.next_u32() & 1U) == 1U
  })
  let input_key = @lwe.lwe_key_from_binary_secret_unchecked(
    input_dimension, input_bits,
  )
  let glwe = match
    @glwe.glwe_parameters(
      parameters.record.glwe_dimension().value(),
      parameters.record.polynomial_size().value(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let glwe_key = @glwe.glwe_keygen(glwe, key_rng)
  let extracted_key = match glwe_key.to_extracted_lwe_key() {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let lwe_noise = if security_bits == 110 {
    @random.gaussian_boolean_110_lwe_fixture()
  } else {
    @random.gaussian_boolean_128_lwe_fixture()
  }
  let glwe_noise = if security_bits == 110 {
    @random.gaussian_boolean_110_glwe_fixture()
  } else {
    @random.gaussian_boolean_128_glwe_fixture()
  }
  let key_switch_input = extracted_key.parameters()
  let key_switch_output = input_key.parameters()
  let key_switch_decomposition = parameters.record.ks_decomposition()
  let ksk_rows = key_switch_input.value() * key_switch_decomposition.level()
  if ksk_rows <= 0 || ksk_rows > 2_000_000_000 / (key_switch_output.value() + 1) {
    return Err(InvalidParameters)
  }
  let key_switch_data = FixedArray::make(
    ksk_rows * (key_switch_output.value() + 1),
    0U,
  )
  let ksk_generation_start = @bench.monotonic_clock_start()
  match
    @keyswitch.keyswitch_keygen_into(
      extracted_key, input_key, key_switch_decomposition, lwe_noise, bsk_rng, key_switch_data,
    ) {
    Ok(_) => ()
    Err(_) => return Err(InvalidParameters)
  }
  let ksk_generation_us = @bench.monotonic_clock_end(ksk_generation_start)
  let ggsw_parameters = match
    @ggsw.ggsw_parameters(
      glwe,
      parameters.record.pbs_decomposition().base_log(),
      parameters.record.pbs_decomposition().level(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let rows = ggsw_parameters.rows()
  let columns = ggsw_parameters.columns()
  let plan = match
    @provider.fft_plan_new_with_capacity(glwe.polynomial_size(), rows, columns) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let control_size = ggsw_parameters.flat_size()
  if control_size <= 0 {
    return Err(InvalidParameters)
  }
  let fourier_allocation_start = @bench.monotonic_clock_start()
  let context = match
    @provider.pbs_context_new_empty(
      glwe.polynomial_size(),
      input_dimension.value(),
      glwe.glwe_dimension(),
      ggsw_parameters.base_log(),
      ggsw_parameters.level(),
      key_switch_input.value(),
      key_switch_output.value(),
      key_switch_decomposition.base_log(),
      key_switch_decomposition.level(),
      1,
      key_switch_data,
    ) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let mut bsk_fourier_conversion_us = @bench.monotonic_clock_end(
    fourier_allocation_start,
  )
  let mut bsk_coefficient_generation_us = 0.0
  let coefficient_control = FixedArray::make(control_size, 0U)
  let ggsw_workspace = @ggsw.ggsw_encryption_workspace_new(ggsw_parameters)
  for index in 0..<input_dimension.value() {
    let coefficient_generation_start = @bench.monotonic_clock_start()
    match
      @ggsw.ggsw_encrypt_boolean_with_fft_into(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        glwe_noise,
        bsk_rng,
        plan,
        ggsw_workspace,
        coefficient_control,
        0,
      ) {
      Ok(_) => ()
      Err(_) => return Err(InvalidParameters)
    }
    bsk_coefficient_generation_us = bsk_coefficient_generation_us +
      @bench.monotonic_clock_end(coefficient_generation_start)
    let fourier_conversion_start = @bench.monotonic_clock_start()
    match context.set_control(index, coefficient_control) {
      Ok(_) => ()
      Err(_) => return Err(InvalidParameters)
    }
    bsk_fourier_conversion_us = bsk_fourier_conversion_us +
      @bench.monotonic_clock_end(fourier_conversion_start)
  }
  let bootstrap = match
    @pbs.bootstrap_key_from_native_context(
      input_dimension,
      glwe,
      ggsw_parameters,
      key_switch_input,
      key_switch_output,
      key_switch_decomposition,
      @pbs.bootstrap_keyswitch_order(),
      context,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let key_id = @params.key_id_from_words(key_rng.next_u64(), key_rng.next_u64())
  let client : ClientKey = {
    inner: input_key,
    mask_rng,
    noise_rng,
    serialization_rng,
    encryption_noise: lwe_noise,
    parameters,
    key_id,
  }
  let server : ServerKey = { inner: bootstrap, parameters, key_id }
  last_standard_keygen_stage_metrics.val = {
    ksk_generation_us,
    bsk_coefficient_generation_us,
    bsk_fourier_conversion_us,
  }
  Ok((client, server))
}
