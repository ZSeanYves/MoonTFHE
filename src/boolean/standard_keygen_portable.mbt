///|
fn generate_standard_keys_impl(
  _parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  Err(UnsupportedBackend)
}
