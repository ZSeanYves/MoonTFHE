///|
pub struct LweDimension {
  value : Int
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
pub enum NoiseDistribution {
  Gaussian(Double)
  TUniform(Int)
} derive(Debug, Eq)

///|
pub struct ParameterSet {
  id : String
  target_security_bits : Int
  upstream_security_bits : Int
  failure_exponent : Double
  lwe_dimension : LweDimension
  glwe_dimension : GlweDimension
  polynomial_size : PolynomialSize
  pbs_decomposition : DecompositionParameters
  ks_decomposition : DecompositionParameters
  noise : NoiseDistribution
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
fn parameter_set(
  id : String,
  target_security_bits : Int,
  upstream_security_bits : Int,
  failure_exponent : Double,
  lwe_dimension : Int,
  glwe_dimension : Int,
  polynomial_size : Int,
  pbs_base_log : Int,
  pbs_level : Int,
  ks_base_log : Int,
  ks_level : Int,
  sigma : Double,
) -> ParameterSet {
  {
    id,
    target_security_bits,
    upstream_security_bits,
    failure_exponent,
    lwe_dimension: { value: lwe_dimension },
    glwe_dimension: { value: glwe_dimension },
    polynomial_size: { value: polynomial_size },
    pbs_decomposition: { base_log: pbs_base_log, level: pbs_level },
    ks_decomposition: { base_log: ks_base_log, level: ks_level },
    noise: Gaussian(sigma),
    estimator_commit: "tfhe-rs-1.7.0:640911e".to_string(),
    reference_only: true,
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
    -64.344,
    805,
    3,
    512,
    10,
    2,
    3,
    5,
    0.0000058615896642671336,
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
    -165.434,
    837,
    2,
    1024,
    10,
    2,
    3,
    5,
    0.000003374714376692653,
  )
}

///|
/// Small structural record used only for deterministic facade tests.
pub fn boolean_test_record() -> ParameterSet {
  parameter_set(
    "moontfhe-boolean-test".to_string(),
    0,
    0,
    -1.0,
    4,
    1,
    32,
    4,
    8,
    4,
    8,
    1.0,
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
  if self.failure_exponent >= 0.0 {
    return Err(InvalidFailureExponent)
  }
  match self.noise {
    Gaussian(sigma) => if sigma <= 0.0 { return Err(UnsupportedDistribution) }
    TUniform(width) => if width <= 0 { return Err(UnsupportedDistribution) }
  }
  Ok(())
}

///|
pub fn ParameterSet::id(self : ParameterSet) -> String {
  self.id
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
pub fn ParameterSet::failure_exponent(self : ParameterSet) -> Double {
  self.failure_exponent
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
}

///|
test "params: malformed failure records are rejected" {
  let invalid = parameter_set(
    "invalid".to_string(),
    110,
    110,
    0.0,
    805,
    3,
    512,
    10,
    2,
    3,
    5,
    0.1,
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
