///|
pub struct LweDimension {
  value : Int
} derive(Debug, Eq)

///|
/// Stable identity attached to a key/ciphertext family. It is an identifier,
/// not a secret and never derives encryption keys.
pub struct KeyId {
  value : Int
} derive(Debug, Eq)

///|
pub fn key_id_from_int(value : Int) -> KeyId {
  { value, }
}

///|
pub fn KeyId::to_int(self : KeyId) -> Int {
  self.value
}

///|
/// Security metadata is descriptive until a fixed estimator has validated the
/// complete MoonTFHE sampling and decomposition assumptions.
pub struct SecurityMetadata {
  target_security_bits : Int
  failure_log2_milli : Int
  estimator_commit : String
  reference_only : Bool
} derive(Debug, Eq)

///|
pub struct GlweDimension {
  value : Int
} derive(Debug, Eq)

///|
pub struct PolynomialSize {
  value : Int
} derive(Debug, Eq)

///|
pub struct DecompositionParameters {
  base_log : Int
  level : Int
} derive(Debug, Eq)

///|
pub struct QuantizedGaussian {
  sigma_q64 : UInt64
  tail_sigma : Int
  fixture_hash : String
} derive(Debug, Eq)

///|
pub enum NoiseDistribution {
  Gaussian(QuantizedGaussian)
  TUniform(Int)
} derive(Debug, Eq)

///|
pub struct FailureProbability {
  log2_milli : Int
} derive(Debug, Eq)

///|
pub struct ParameterSet {
  id : String
  target_security_bits : Int
  upstream_security_bits : Int
  failure_probability : FailureProbability
  lwe_dimension : LweDimension
  glwe_dimension : GlweDimension
  polynomial_size : PolynomialSize
  pbs_decomposition : DecompositionParameters
  ks_decomposition : DecompositionParameters
  lwe_noise : NoiseDistribution
  glwe_noise : NoiseDistribution
  estimator_commit : String
  reference_only : Bool
} derive(Debug)

///|
pub suberror ParameterValidationError {
  InvalidDimension
  InvalidPolynomialSize
  InvalidDecomposition
  InvalidFailureExponent
  UnsupportedDistribution
} derive(Debug, Eq)

///|
pub fn decomposition_parameters(
  base_log : Int,
  level : Int,
) -> Result[DecompositionParameters, ParameterValidationError] {
  if base_log <= 0 || level <= 0 || base_log * level > 32 {
    Err(InvalidDecomposition)
  } else {
    Ok({ base_log, level })
  }
}

///|
fn parameter_set(
  id : String,
  target_security_bits : Int,
  upstream_security_bits : Int,
  failure_log2_milli : Int,
  lwe_dimension : Int,
  glwe_dimension : Int,
  polynomial_size : Int,
  pbs_base_log : Int,
  pbs_level : Int,
  ks_base_log : Int,
  ks_level : Int,
  lwe_sigma_q64 : UInt64,
  glwe_sigma_q64 : UInt64,
) -> ParameterSet {
  {
    id,
    target_security_bits,
    upstream_security_bits,
    failure_probability: { log2_milli: failure_log2_milli },
    lwe_dimension: { value: lwe_dimension },
    glwe_dimension: { value: glwe_dimension },
    polynomial_size: { value: polynomial_size },
    pbs_decomposition: { base_log: pbs_base_log, level: pbs_level },
    ks_decomposition: { base_log: ks_base_log, level: ks_level },
    lwe_noise: Gaussian({
      sigma_q64: lwe_sigma_q64,
      tail_sigma: 8,
      fixture_hash: "unavailable:reference-only".to_string(),
    }),
    glwe_noise: Gaussian({
      sigma_q64: glwe_sigma_q64,
      tail_sigma: 8,
      fixture_hash: "unavailable:reference-only".to_string(),
    }),
    estimator_commit: "tfhe-rs-1.7.0:640911e".to_string(),
    reference_only: true,
  }
}

///|
pub fn lwe_dimension(
  value : Int,
) -> Result[LweDimension, ParameterValidationError] {
  if value <= 0 {
    Err(InvalidDimension)
  } else {
    Ok({ value, })
  }
}

///|
pub fn glwe_dimension(
  value : Int,
) -> Result[GlweDimension, ParameterValidationError] {
  if value <= 0 {
    Err(InvalidDimension)
  } else {
    Ok({ value, })
  }
}

///|
pub fn polynomial_size(
  value : Int,
) -> Result[PolynomialSize, ParameterValidationError] {
  if value <= 0 || (value & (value - 1)) != 0 {
    Err(InvalidPolynomialSize)
  } else {
    Ok({ value, })
  }
}

///|
/// Upstream Boolean default record. The 110-bit target is a local minimum
/// target; the upstream record reports a stronger claimed security level.
pub fn boolean_110_reference() -> ParameterSet {
  parameter_set(
    "tfhe-rs-boolean-default-reference".to_string(),
    110,
    132,
    -64344,
    805,
    3,
    512,
    10,
    2,
    3,
    5,
    0x625755FE3CADUL,
    0x40039996AUL,
  )
}

///|
/// Upstream Boolean strong record. The 128-bit target is a local minimum
/// target; the upstream record reports a stronger claimed security level.
pub fn boolean_128_reference() -> ParameterSet {
  parameter_set(
    "tfhe-rs-boolean-strong-reference".to_string(),
    128,
    165,
    -165434,
    837,
    2,
    1024,
    10,
    2,
    3,
    5,
    0x389E49B295AEUL,
    0x400000000UL,
  )
}

///|
/// Small structural record used only for deterministic facade tests.
pub fn boolean_test_record() -> ParameterSet {
  parameter_set(
    "moontfhe-boolean-test".to_string(),
    0,
    0,
    -1000,
    4,
    1,
    32,
    4,
    8,
    4,
    8,
    3UL << 32,
    3UL << 32,
  )
}

///|
pub fn ParameterSet::validate(
  self : ParameterSet,
) -> Result[Unit, ParameterValidationError] {
  if self.lwe_dimension.value <= 0 || self.glwe_dimension.value <= 0 {
    return Err(InvalidDimension)
  }
  let n = self.polynomial_size.value
  if n <= 0 || (n & (n - 1)) != 0 {
    return Err(InvalidPolynomialSize)
  }
  for decomposition in [self.pbs_decomposition, self.ks_decomposition] {
    if decomposition.base_log <= 0 ||
      decomposition.level <= 0 ||
      decomposition.base_log * decomposition.level > 32 {
      return Err(InvalidDecomposition)
    }
  }
  if self.failure_probability.log2_milli >= 0 {
    return Err(InvalidFailureExponent)
  }
  for noise in [self.lwe_noise, self.glwe_noise] {
    match noise {
      Gaussian(distribution) =>
        if distribution.sigma_q64 == 0UL || distribution.tail_sigma <= 0 {
          return Err(UnsupportedDistribution)
        }
      TUniform(width) => if width <= 0 { return Err(UnsupportedDistribution) }
    }
  }
  Ok(())
}

///|
pub fn ParameterSet::id(self : ParameterSet) -> String {
  self.id
}

///|
pub fn ParameterSet::security_metadata(self : ParameterSet) -> SecurityMetadata {
  {
    target_security_bits: self.target_security_bits,
    failure_log2_milli: self.failure_probability.log2_milli,
    estimator_commit: self.estimator_commit,
    reference_only: self.reference_only,
  }
}

///|
pub fn SecurityMetadata::target_security_bits(self : SecurityMetadata) -> Int {
  self.target_security_bits
}

///|
pub fn SecurityMetadata::failure_log2_milli(self : SecurityMetadata) -> Int {
  self.failure_log2_milli
}

///|
pub fn SecurityMetadata::estimator_commit(self : SecurityMetadata) -> String {
  self.estimator_commit
}

///|
pub fn SecurityMetadata::is_reference_only(self : SecurityMetadata) -> Bool {
  self.reference_only
}

///|
pub fn ParameterSet::target_security_bits(self : ParameterSet) -> Int {
  self.target_security_bits
}

///|
pub fn ParameterSet::upstream_security_bits(self : ParameterSet) -> Int {
  self.upstream_security_bits
}

///|
pub fn ParameterSet::failure_log2_milli(self : ParameterSet) -> Int {
  self.failure_probability.log2_milli
}

///|
pub fn QuantizedGaussian::sigma_q64(self : QuantizedGaussian) -> UInt64 {
  self.sigma_q64
}

///|
pub fn QuantizedGaussian::tail_sigma(self : QuantizedGaussian) -> Int {
  self.tail_sigma
}

///|
pub fn QuantizedGaussian::fixture_hash(self : QuantizedGaussian) -> String {
  self.fixture_hash
}

///|
pub fn ParameterSet::lwe_noise(self : ParameterSet) -> NoiseDistribution {
  self.lwe_noise
}

///|
pub fn ParameterSet::glwe_noise(self : ParameterSet) -> NoiseDistribution {
  self.glwe_noise
}

///|
pub fn ParameterSet::estimator_commit(self : ParameterSet) -> String {
  self.estimator_commit
}

///|
pub fn ParameterSet::is_reference_only(self : ParameterSet) -> Bool {
  self.reference_only
}

///|
pub fn LweDimension::value(self : LweDimension) -> Int {
  self.value
}

///|
pub fn GlweDimension::value(self : GlweDimension) -> Int {
  self.value
}

///|
pub fn PolynomialSize::value(self : PolynomialSize) -> Int {
  self.value
}

///|
pub fn DecompositionParameters::base_log(self : DecompositionParameters) -> Int {
  self.base_log
}

///|
pub fn DecompositionParameters::level(self : DecompositionParameters) -> Int {
  self.level
}

///|
test "params: reference records are structurally valid" {
  let low = boolean_110_reference()
  let high = boolean_128_reference()
  assert_true(low.validate() is Ok(_))
  assert_true(high.validate() is Ok(_))
  assert_eq(low.target_security_bits(), 110)
  assert_eq(high.target_security_bits(), 128)
  assert_true(low.is_reference_only())
  assert_true(high.is_reference_only())
  let metadata = high.security_metadata()
  assert_eq(metadata.target_security_bits(), 128)
  assert_eq(metadata.failure_log2_milli(), high.failure_log2_milli())
  assert_eq(metadata.estimator_commit(), high.estimator_commit())
  assert_true(metadata.is_reference_only())
  assert_eq(key_id_from_int(-1).to_int(), -1)
}

///|
test "params: malformed failure records are rejected" {
  let invalid = parameter_set(
    "invalid".to_string(),
    110,
    110,
    0,
    805,
    3,
    512,
    10,
    2,
    3,
    5,
    1UL,
    1UL,
  )
  assert_true(invalid.validate() is Err(InvalidFailureExponent))
}

///|
test "params: supported noise variants are explicit" {
  let distribution : NoiseDistribution = TUniform(4)
  match distribution {
    TUniform(width) => assert_eq(width, 4)
    Gaussian(_) => fail("unexpected Gaussian variant")
  }
}
