///|
fn rebuild_fourier_cache(
  parameters : BooleanParameters,
  ggsw : @ggsw.GgswParameters,
  coefficients : FixedArray[UInt],
) -> Result[@provider.FourierBootstrapKey?, SerializationError] {
  if parameters.test_only {
    return Ok(None)
  }
  let plan = match
    @provider.fft_plan_new_with_capacity(
      parameters.record.polynomial_size().value(),
      ggsw.rows(),
      ggsw.columns(),
    ) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  match
    @provider.fourier_bsk_new(
      plan,
      coefficients,
      parameters.record.lwe_dimension().value(),
      ggsw.rows(),
      ggsw.columns(),
    ) {
    Ok(value) => Ok(Some(value))
    Err(_) => Err(InvalidServerKey)
  }
}
