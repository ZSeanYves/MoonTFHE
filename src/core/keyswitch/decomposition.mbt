///|
pub suberror DecompositionError {
  InvalidParameters
  InsufficientLevels
} derive(Debug, Eq)

///|
/// Signed balanced gadget digits, ordered least-significant level first.
pub fn signed_decompose(
  value : @torus.Torus32,
  parameters : @params.DecompositionParameters,
) -> Result[Array[Int], DecompositionError] {
  let base_log = parameters.base_log()
  let level = parameters.level()
  if base_log <= 0 || base_log >= 31 || level <= 0 || base_log * level > 32 {
    return Err(InvalidParameters)
  }
  let base = 1 << base_log
  let mask = (base - 1).reinterpret_as_uint()
  let half = base / 2
  let mut remaining = value.to_uint()
  let digits = Array::makei(level, fn(_) { 0 })
  for index in 0..<level {
    let unsigned_digit = (remaining & mask).reinterpret_as_int()
    if unsigned_digit >= half {
      digits[index] = unsigned_digit - base
      remaining = (remaining >> base_log) + 1U
    } else {
      digits[index] = unsigned_digit
      remaining = remaining >> base_log
    }
  }
  // Standard gadget decompositions intentionally truncate high remainder bits;
  // callers that require an exact reconstruction use the strict wrapper.
  Ok(digits)
}

///|
pub fn signed_decompose_exact(
  value : @torus.Torus32,
  parameters : @params.DecompositionParameters,
) -> Result[Array[Int], DecompositionError] {
  if parameters.base_log() * parameters.level() < 32 {
    return Err(InsufficientLevels)
  }
  signed_decompose(value, parameters)
}

///|
/// Decompose the rounded most-significant gadget bits using balanced digits.
/// Digits are ordered from the largest gadget weight to the smallest.
pub fn signed_gadget_decompose(
  value : @torus.Torus32,
  parameters : @params.DecompositionParameters,
) -> Result[Array[Int], DecompositionError] {
  let base_log = parameters.base_log()
  let level = parameters.level()
  let total_bits = base_log * level
  if base_log <= 0 || base_log >= 31 || level <= 0 || total_bits > 32 {
    return Err(InvalidParameters)
  }
  let discarded_bits = 32 - total_bits
  let rounded = if discarded_bits == 0 {
    value.to_uint()
  } else {
    value.to_uint() + (1U << (discarded_bits - 1))
  }
  let state = if discarded_bits == 0 {
    rounded
  } else {
    rounded >> discarded_bits
  }
  let base = 1 << base_log
  let half = base / 2
  let mask = (base - 1).reinterpret_as_uint()
  let digits = Array::make(level, 0)
  let mut carry = 0
  for offset in 0..<level {
    let index = level - 1 - offset
    let shift = (level - 1 - index) * base_log
    let unsigned_digit = ((state >> shift) & mask).reinterpret_as_int() + carry
    if unsigned_digit >= half {
      digits[index] = unsigned_digit - base
      carry = 1
    } else {
      digits[index] = unsigned_digit
      carry = 0
    }
  }
  Ok(digits)
}

///|
pub struct KeySwitchKey {
  input_parameters : @params.LweDimension
  output_parameters : @params.LweDimension
  decomposition : @params.DecompositionParameters
  rows : Array[Array[@lwe.LweCiphertext]]
}

///|
pub suberror KeySwitchError {
  InvalidInputDimension
  InvalidOutputDimension
  InvalidDecomposition
  CiphertextError
} derive(Debug, Eq)

///|
/// Generate a KSK whose rows encrypt input-key bits under the target key.
pub fn keyswitch_keygen(
  input : @lwe.LweSecretKey,
  target : @lwe.LweSecretKey,
  decomposition : @params.DecompositionParameters,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[KeySwitchKey, KeySwitchError] {
  if decomposition.base_log() <= 0 ||
    decomposition.level() <= 0 ||
    decomposition.base_log() * decomposition.level() > 32 {
    return Err(InvalidDecomposition)
  }
  let rows : Array[Array[@lwe.LweCiphertext]] = []
  for index in 0..<input.parameters().value() {
    match
      input.encrypt_secret_gadget_row(index, target, decomposition, noise, rng) {
      Ok(row) => rows.push(row)
      Err(_) => return Err(CiphertextError)
    }
  }
  Ok({
    input_parameters: input.parameters(),
    output_parameters: target.parameters(),
    decomposition,
    rows,
  })
}

///|
pub fn KeySwitchKey::apply(
  self : KeySwitchKey,
  ciphertext : @lwe.LweCiphertext,
) -> Result[@lwe.LweCiphertext, KeySwitchError] {
  if ciphertext.parameters() != self.input_parameters {
    return Err(InvalidInputDimension)
  }
  let mut result = @lwe.lwe_trivial(self.output_parameters, ciphertext.b())
  let mask = ciphertext.a()
  for index in 0..<mask.length() {
    let digits = match
      signed_gadget_decompose(mask[index], self.decomposition) {
      Ok(value) => value
      Err(_) => return Err(InvalidDecomposition)
    }
    for level in 0..<digits.length() {
      result = match result.sub_scaled(self.rows[index][level], digits[level]) {
        Ok(value) => value
        Err(_) => return Err(CiphertextError)
      }
    }
  }
  Ok(result)
}

///|
test "keyswitch: encrypted gadget rows preserve an LWE message" {
  let input = @lwe.lwe_keygen(
    @params.lwe_dimension(4).unwrap(),
    @random.test_rng_new(0x494E505554),
  )
  let target = @lwe.lwe_keygen(
    @params.lwe_dimension(4).unwrap(),
    @random.test_rng_new(0x544152474554),
  )
  let decomposition = @params.decomposition_parameters(4, 8).unwrap()
  let ksk = keyswitch_keygen(
    input,
    target,
    decomposition,
    @random.gaussian_sigma_3_fixture(),
    @random.test_rng_new(0x4B534B),
  ).unwrap()
  let ciphertext = input
    .lwe_encrypt_binary(
      true,
      @random.gaussian_sigma_3_fixture(),
      @random.test_rng_new(9),
    )
    .unwrap()
  let switched = ksk.apply(ciphertext).unwrap()
  assert_eq(target.lwe_decrypt_binary(switched), Ok(true))
}

///|
pub fn signed_recompose(
  digits : Array[Int],
  parameters : @params.DecompositionParameters,
) -> Result[@torus.Torus32, DecompositionError] {
  if digits.length() != parameters.level() {
    return Err(InvalidParameters)
  }
  let base_log = parameters.base_log()
  if base_log <= 0 || base_log >= 31 || base_log * parameters.level() > 32 {
    return Err(InvalidParameters)
  }
  let mut value = 0L
  let base = 1L << base_log
  let mut factor = 1L
  for digit in digits {
    if digit < -(base.to_int() / 2) || digit >= base.to_int() / 2 {
      return Err(InvalidParameters)
    }
    value = value + digit.to_int64() * factor
    factor = factor * base
  }
  Ok(@torus.Torus32::from_uint(value.reinterpret_as_uint64().to_uint()))
}

///|
test "keyswitch: signed decomposition reconstructs full-width torus" {
  let parameters = @params.decomposition_parameters(4, 8).unwrap()
  let values = [0U, 1U, 0x7FFF_FFFFU, 0x8000_0000U, 0xFFFF_FFFFU]
  for value in values {
    let digits = signed_decompose_exact(
      @torus.Torus32::from_uint(value),
      parameters,
    ).unwrap()
    let reconstructed = signed_recompose(digits, parameters).unwrap()
    assert_eq(reconstructed.to_uint(), value)
  }
}

///|
test "keyswitch: signed gadget decomposition reconstructs full-width torus" {
  let parameters = @params.decomposition_parameters(4, 8).unwrap()
  let values = [0U, 1U, 0x7FFF_FFFFU, 0x8000_0000U, 0xFFFF_FFFFU]
  for value in values {
    let digits = signed_gadget_decompose(
      @torus.Torus32::from_uint(value),
      parameters,
    ).unwrap()
    let mut reconstructed = @torus.Torus32::zero()
    for level_index in 0..<digits.length() {
      let shift = 32 - parameters.base_log() * (level_index + 1)
      reconstructed = reconstructed.add(
        @torus.Torus32::from_uint(1U << shift).scale(digits[level_index]),
      )
    }
    assert_eq(reconstructed.to_uint(), value)
  }
}

///|
test "keyswitch: insufficient levels are explicit" {
  let parameters = @params.decomposition_parameters(10, 2).unwrap()
  assert_true(
    signed_decompose_exact(@torus.Torus32::from_uint(0xFFFF_FFFFU), parameters)
    is Err(InsufficientLevels),
  )
}
