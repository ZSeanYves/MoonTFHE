///|
fn rebuild_fourier_cache(
  _parameters : BooleanParameters,
  _ggsw : @ggsw.GgswParameters,
  _coefficients : FixedArray[UInt],
) -> Result[@provider.FourierBootstrapKey?, SerializationError] {
  Ok(None)
}
