///|
pub struct LweDimension {
  value : Int
} derive(Debug, Eq)

///|
/// Stable identity attached to a key/ciphertext family. It is an identifier,
/// not a secret and never derives encryption keys.
pub struct KeyId {
  high : UInt64
  low : UInt64
} derive(Debug, Eq)

///|
pub fn key_id_from_words(high : UInt64, low : UInt64) -> KeyId {
  { high, low }
}

///|
pub fn KeyId::high(self : KeyId) -> UInt64 {
  self.high
}

///|
pub fn KeyId::low(self : KeyId) -> UInt64 {
  self.low
}

///|
/// Security metadata is generated from MoonTFHE's fixed estimator and noise
/// fixtures. It remains a model-based claim, not an independent audit.
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
  sigma_q32 : UInt64
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
  lwe_sigma_q32 : UInt64,
  glwe_sigma_q32 : UInt64,
  reference_only : Bool,
) -> ParameterSet {
  let lwe_fixture_hash = if lwe_sigma_q32 == 0x625755FE3CADUL {
    "sha256:ee48d57a2b4d605a1240bd0c0091d687d3a271ca01cb6445181ab0ebd231e9b2"
  } else if lwe_sigma_q32 == 0x389E49B295AEUL {
    "sha256:b656bcec091f9df2fcd7168769c63c7cb50fc0f1703879a54e2c94c440f6afb5"
  } else {
    "unavailable:reference-only"
  }
  let glwe_fixture_hash = if glwe_sigma_q32 == 0x40039996AUL {
    "sha256:d5c6cc61710e896ed6c9ce217f51353b42a4eea2a68da304a26eb9bd9a65df7d"
  } else if glwe_sigma_q32 == 0x400000000UL {
    "sha256:08cdeccdba967b897d7782fa14f4282ac7796a79df9dc6a998ddedf49f35a68d"
  } else {
    "unavailable:reference-only"
  }
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
      sigma_q32: lwe_sigma_q32,
      tail_sigma: 16,
      fixture_hash: lwe_fixture_hash.to_string(),
    }),
    glwe_noise: Gaussian({
      sigma_q32: glwe_sigma_q32,
      tail_sigma: 16,
      fixture_hash: glwe_fixture_hash.to_string(),
    }),
    estimator_commit: "lattice-estimator:3e48ef4;tfhe-rs:640911e".to_string(),
    reference_only,
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
/// Boolean 110-bit production record. The lattice estimate is 132.014875
/// bits and the fixed-point union bound is at most 2^-159.374.
pub fn boolean_110_reference() -> ParameterSet {
  parameter_set(
    "tfhe-rs-boolean-default-reference".to_string(),
    110,
    132,
    -159374,
    805,
    3,
    512,
    10,
    2,
    3,
    5,
    0x625755FE3CADUL,
    0x40039996AUL,
    false,
  )
}

///|
/// Boolean 128-bit production record. The lattice estimate is 132.050320
/// bits and the fixed-point union bound is at most 2^-159.662.
pub fn boolean_128_reference() -> ParameterSet {
  parameter_set(
    "tfhe-rs-boolean-strong-reference".to_string(),
    128,
    132,
    -159662,
    837,
    2,
    1024,
    10,
    2,
    3,
    5,
    0x389E49B295AEUL,
    0x400000000UL,
    false,
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
    true,
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
        if distribution.sigma_q32 == 0UL || distribution.tail_sigma <= 0 {
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
pub fn ParameterSet::lwe_dimension(self : ParameterSet) -> LweDimension {
  self.lwe_dimension
}

///|
pub fn ParameterSet::glwe_dimension(self : ParameterSet) -> GlweDimension {
  self.glwe_dimension
}

///|
pub fn ParameterSet::polynomial_size(self : ParameterSet) -> PolynomialSize {
  self.polynomial_size
}

///|
pub fn ParameterSet::pbs_decomposition(
  self : ParameterSet,
) -> DecompositionParameters {
  self.pbs_decomposition
}

///|
pub fn ParameterSet::ks_decomposition(
  self : ParameterSet,
) -> DecompositionParameters {
  self.ks_decomposition
}

///|
pub fn QuantizedGaussian::sigma_q32(self : QuantizedGaussian) -> UInt64 {
  self.sigma_q32
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
  assert_false(low.is_reference_only())
  assert_false(high.is_reference_only())
  let metadata = high.security_metadata()
  assert_eq(metadata.target_security_bits(), 128)
  assert_eq(metadata.failure_log2_milli(), high.failure_log2_milli())
  assert_eq(metadata.estimator_commit(), high.estimator_commit())
  assert_false(metadata.is_reference_only())
  let key_id = key_id_from_words(0x0123456789ABCDEFUL, 0xFEDCBA9876543210UL)
  assert_eq(key_id.high(), 0x0123456789ABCDEFUL)
  assert_eq(key_id.low(), 0xFEDCBA9876543210UL)
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
    true,
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
