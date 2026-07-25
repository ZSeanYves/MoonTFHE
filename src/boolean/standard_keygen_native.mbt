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
  let key_switch = match
    @keyswitch.keyswitch_keygen(
      extracted_key,
      input_key,
      parameters.record.ks_decomposition(),
      lwe_noise,
      bsk_rng,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
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
  let coefficient_bsk = FixedArray::make(
    input_dimension.value() * control_size,
    0U,
  )
  for index in 0..<input_dimension.value() {
    let control = match
      @ggsw.ggsw_encrypt_boolean_with_fft(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        glwe_noise,
        bsk_rng,
        plan,
      ) {
      Ok(value) => value
      Err(_) => return Err(InvalidParameters)
    }
    let flat = control.flat_u32_copy()
    for offset in 0..<control_size {
      coefficient_bsk[index * control_size + offset] = flat[offset]
    }
  }
  let fourier = match
    @provider.fourier_bsk_new(
      plan,
      coefficient_bsk,
      input_dimension.value(),
      rows,
      columns,
    ) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let bootstrap = match
    @pbs.bootstrap_key_from_flat_encrypted_parts(
      input_dimension,
      glwe,
      ggsw_parameters,
      coefficient_bsk,
      key_switch,
      @pbs.bootstrap_keyswitch_order(),
      Some(fourier),
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
  Ok((client, server))
}
