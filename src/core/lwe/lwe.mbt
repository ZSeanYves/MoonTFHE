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
  InvalidIndex
  InvalidDecomposition
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
/// Construct a low-level LWE key from caller-owned binary key material.
/// High-level key generation keeps the input array local and never exposes it
/// through `LweSecretKey` accessors.
pub fn lwe_key_from_binary_secret(
  parameters : @params.LweDimension,
  bits : Array[Bool],
) -> Result[LweSecretKey, LweError] {
  if bits.length() != parameters.value() {
    return Err(InvalidDimension)
  }
  Ok({ parameters, bits: bits.copy() })
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
  let encoded = if message {
    @torus.Torus32::from_int(0x2000_0000)
  } else {
    @torus.Torus32::from_int(-0x2000_0000)
  }
  self.lwe_encrypt_torus(encoded, noise, rng)
}

///|
pub fn LweSecretKey::lwe_encrypt_torus(
  self : LweSecretKey,
  message : @torus.Torus32,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[LweCiphertext, LweError] {
  let n = self.parameters.value()
  let a = Array::makei(n, fn(_) { @torus.Torus32::from_uint(rng.next_u32()) })
  let mut phase = message
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
pub fn lwe_trivial(
  parameters : @params.LweDimension,
  message : @torus.Torus32,
) -> LweCiphertext {
  {
    parameters,
    a: Array::make(parameters.value(), @torus.Torus32::zero()),
    b: message,
  }
}

///|
pub fn LweCiphertext::sub_scaled(
  self : LweCiphertext,
  other : LweCiphertext,
  scalar : Int,
) -> Result[LweCiphertext, LweError] {
  if self.parameters != other.parameters || self.a.length() != other.a.length() {
    return Err(CiphertextDimensionMismatch)
  }
  Ok({
    parameters: self.parameters,
    a: Array::makei(self.a.length(), fn(i) {
      self.a[i].sub(other.a[i].scale(scalar))
    }),
    b: self.b.sub(other.b.scale(scalar)),
  })
}

///|
/// Encrypt one input-key bit multiplied by every gadget power. This keygen
/// hook never returns the secret bit itself.
pub fn LweSecretKey::encrypt_secret_gadget_row(
  self : LweSecretKey,
  index : Int,
  target : LweSecretKey,
  decomposition : @params.DecompositionParameters,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[Array[LweCiphertext], LweError] {
  if index < 0 || index >= self.bits.length() {
    return Err(InvalidIndex)
  }
  let base_log = decomposition.base_log()
  let level = decomposition.level()
  if base_log <= 0 || level <= 0 || base_log * level > 32 {
    return Err(InvalidDecomposition)
  }
  let result : Array[LweCiphertext] = []
  for level_index in 0..<level {
    let shift = 32 - base_log * (level_index + 1)
    let gadget = 1U << shift
    let plaintext = if self.bits[index] {
      @torus.Torus32::from_uint(gadget)
    } else {
      @torus.Torus32::zero()
    }
    match target.lwe_encrypt_torus(plaintext, noise, rng) {
      Ok(ciphertext) => result.push(ciphertext)
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn LweSecretKey::parameters(self : LweSecretKey) -> @params.LweDimension {
  self.parameters
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
