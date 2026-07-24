///|
/// Errors returned by the operating-system entropy adapter.
pub suberror SecureRandomError {
  UnsupportedBackend
  EntropyUnavailable
} derive(Debug, Eq)

///|
/// A handle for the reviewed system entropy backend. It intentionally has no
/// deterministic seed or mutable PRNG state.
pub struct SecureRng {
  ready : Bool
}

///|
/// Create a secure entropy source for the current backend.
pub fn secure_rng_new() -> Result[SecureRng, SecureRandomError] {
  if !secure_rng_backend_available() {
    return Err(UnsupportedBackend)
  }
  Ok({ ready: true })
}

///|
/// Read one operating-system random word.
pub fn SecureRng::next_u64(
  self : SecureRng,
) -> Result[UInt64, SecureRandomError] {
  if !self.ready {
    return Err(EntropyUnavailable)
  }
  Ok(secure_rng_backend_next())
}

///|
/// Draw a uniform floating-point value in [0, 1).
pub fn SecureRng::uniform_01(
  self : SecureRng,
) -> Result[Float, SecureRandomError] {
  let word = match self.next_u64() {
    Ok(word) => word
    Err(error) => return Err(error)
  }
  let mantissa = word >> 11
  Ok(Float::from_double(mantissa.to_double() / 9007199254740992.0))
}

///|
/// Draw a rounded normal sample using independent system-random uniforms.
/// This is a transitional sampler; P3 will replace it with the audited
/// parameter-specific distribution used by the TFHE evaluator.
pub fn SecureRng::gaussian(
  self : SecureRng,
  sigma : Float,
) -> Result[Int, SecureRandomError] {
  if sigma <= 0.0 {
    return Ok(0)
  }
  let mut u1 = match self.uniform_01() {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let u2 = match self.uniform_01() {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if u1 == 0.0 {
    u1 = 0.0000000000000001
  }
  let radius = (-2.0 * @math.ln(u1.to_double())).sqrt()
  let sample = radius *
    @math.cos(2.0 * @math.PI * u2.to_double()) *
    sigma.to_double()
  Ok(sample.round().to_int())
}

///|
test "secure rng: backend capability is explicit" {
  let result = secure_rng_new()
  match result {
    Ok(rng) => {
      let word = rng.next_u64()
      assert_true(word is Ok(_))
    }
    Err(UnsupportedBackend) => assert_true(true)
    Err(EntropyUnavailable) => assert_true(true)
  }
}
