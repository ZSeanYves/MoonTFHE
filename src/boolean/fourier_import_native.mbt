///|
fn rebuild_bootstrap_key(
  parameters : BooleanParameters,
  input_dimension : @params.LweDimension,
  glwe : @glwe.GlweParameters,
  ggsw : @ggsw.GgswParameters,
  coefficients : FixedArray[UInt],
  key_switch_input : @params.LweDimension,
  key_switch_data : FixedArray[UInt],
  order : @pbs.PbsOrder,
) -> Result[@pbs.BootstrapKey, SerializationError] {
  match
    @pbs.bootstrap_key_from_flat_native_parts(
      input_dimension,
      glwe,
      ggsw,
      coefficients,
      key_switch_input,
      input_dimension,
      parameters.record.ks_decomposition(),
      key_switch_data,
      order,
    ) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidServerKey)
  }
}
