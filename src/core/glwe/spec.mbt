///|
declare pub type GlweParameters

///|
declare pub type GlweSecretKey

///|
declare pub type GlweCiphertext

///|
declare pub fn glwe_parameters(
  glwe_dimension : Int,
  polynomial_size : Int,
) -> Result[GlweParameters, GlweError]

///|
declare pub fn glwe_keygen(
  parameters : GlweParameters,
  rng : @random.RandomGenerator,
) -> GlweSecretKey
