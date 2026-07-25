///|
fn generate_standard_keys_impl(
  parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  generate_standard_reference_keys(parameters)
}
