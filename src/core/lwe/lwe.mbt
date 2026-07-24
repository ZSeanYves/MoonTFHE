///|
pub struct LweSecretKey {
  parameters : @params.LweDimension
  bits : Array[Bool]
}

///|
pub struct LweCiphertext {
  parameters : @params.LweDimension
  a : Array[@torus.Torus32]
  b : @torus.Torus32
} derive(Debug, Eq)

///|
pub suberror LweError {
  InvalidDimension
  CiphertextDimensionMismatch
  NoiseFailure
} derive(Debug, Eq)

///|
pub fn lwe_keygen(
  parameters : @params.LweDimension,
  rng : @random.RandomGenerator,
) -> LweSecretKey {
  let n = parameters.value()
  { parameters, bits: Array::makei(n, fn(_) { (rng.next_u32() & 1U) == 1U }) }
}

///|
/// Construct a ciphertext from a validated sample-extraction layout.
pub fn lwe_ciphertext_from_parts(
  parameters : @params.LweDimension,
  a : Array[@torus.Torus32],
  b : @torus.Torus32,
) -> Result[LweCiphertext, LweError] {
  if a.length() != parameters.value() {
    Err(CiphertextDimensionMismatch)
  } else {
    Ok({ parameters, a, b })
  }
}

///|
pub fn LweSecretKey::lwe_encrypt_binary(
  self : LweSecretKey,
  message : Bool,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[LweCiphertext, LweError] {
  let n = self.parameters.value()
  let a = Array::makei(n, fn(_) { @torus.Torus32::from_uint(rng.next_u32()) })
  let mut phase = if message {
    @torus.Torus32::from_int(0x2000_0000)
  } else {
    @torus.Torus32::from_int(-0x2000_0000)
  }
  for i in 0..<n {
    if self.bits[i] {
      phase = phase.add(a[i])
    }
  }
  let error = match rng.sample_discrete_gaussian_fixed(noise) {
    Ok(value) => value
    Err(_) => return Err(NoiseFailure)
  }
  Ok({
    parameters: self.parameters,
    a,
    b: phase.add(@torus.Torus32::from_int(error)),
  })
}

///|
pub fn LweSecretKey::lwe_decrypt_binary(
  self : LweSecretKey,
  ciphertext : LweCiphertext,
) -> Result[Bool, LweError] {
  if ciphertext.parameters != self.parameters ||
    ciphertext.a.length() != self.bits.length() {
    return Err(CiphertextDimensionMismatch)
  }
  let mut phase = ciphertext.b
  for i in 0..<self.bits.length() {
    if self.bits[i] {
      phase = phase.sub(ciphertext.a[i])
    }
  }
  Ok(phase.decode_sign())
}

///|
pub fn LweCiphertext::parameters(self : LweCiphertext) -> @params.LweDimension {
  self.parameters
}

///|
pub fn LweCiphertext::a(self : LweCiphertext) -> Array[@torus.Torus32] {
  self.a
}

///|
pub fn LweCiphertext::b(self : LweCiphertext) -> @torus.Torus32 {
  self.b
}

///|
test "lwe core: typed key and ciphertext round trip" {
  let dimension = @params.lwe_dimension(32).unwrap()
  let key = lwe_keygen(dimension, @random.test_rng_new(0x4C5745434F5245))
  let ciphertext = key
    .lwe_encrypt_binary(
      true,
      @random.gaussian_sigma_3_fixture(),
      @random.test_rng_new(7),
    )
    .unwrap()
  assert_eq(key.lwe_decrypt_binary(ciphertext), Ok(true))
}
