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
  let key_switch = match
    @keyswitch.keyswitch_key_from_owned_flat_u32(
      key_switch_input,
      input_dimension,
      parameters.record.ks_decomposition(),
      key_switch_data,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  match
    @pbs.bootstrap_key_from_flat_encrypted_parts(
      input_dimension,
      glwe,
      ggsw,
      coefficients,
      key_switch,
      order,
      None,
    ) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidServerKey)
  }
}
