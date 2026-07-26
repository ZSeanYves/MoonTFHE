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
/// Allocation-free variant for hot paths. Digits use the same largest-to-
/// smallest gadget-weight order as `signed_gadget_decompose`.
pub fn signed_gadget_decompose_into(
  value : @torus.Torus32,
  parameters : @params.DecompositionParameters,
  digits : FixedArray[Int],
) -> Result[Unit, DecompositionError] {
  let base_log = parameters.base_log()
  let level = parameters.level()
  let total_bits = base_log * level
  if base_log <= 0 ||
    base_log >= 31 ||
    level <= 0 ||
    total_bits > 32 ||
    digits.length() != level {
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
  Ok(())
}

///|
pub struct KeySwitchKey {
  input_parameters : @params.LweDimension
  output_parameters : @params.LweDimension
  decomposition : @params.DecompositionParameters
  data : FixedArray[UInt]
}

///|
pub fn KeySwitchKey::input_dimension(
  self : KeySwitchKey,
) -> @params.LweDimension {
  self.input_parameters
}

///|
pub fn KeySwitchKey::output_dimension(
  self : KeySwitchKey,
) -> @params.LweDimension {
  self.output_parameters
}

///|
pub fn KeySwitchKey::decomposition(
  self : KeySwitchKey,
) -> @params.DecompositionParameters {
  self.decomposition
}

///|
pub fn KeySwitchKey::row_count(self : KeySwitchKey) -> Int {
  self.input_parameters.value()
}

///|
pub fn KeySwitchKey::flat_u32_copy(self : KeySwitchKey) -> FixedArray[UInt] {
  self.data.copy()
}

///|
pub fn keyswitch_key_from_flat_u32(
  input_parameters : @params.LweDimension,
  output_parameters : @params.LweDimension,
  decomposition : @params.DecompositionParameters,
  data : FixedArray[UInt],
) -> Result[KeySwitchKey, KeySwitchError] {
  let expected = input_parameters.value() *
    decomposition.level() *
    (output_parameters.value() + 1)
  if data.length() != expected {
    Err(CiphertextError)
  } else {
    Ok({ input_parameters, output_parameters, decomposition, data: data.copy() })
  }
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
  let level_count = decomposition.level()
  let ciphertext_size = target.parameters().value() + 1
  let data = FixedArray::make(
    input.parameters().value() * level_count * ciphertext_size,
    0U,
  )
  for index in 0..<input.parameters().value() {
    match
      input.encrypt_secret_gadget_row(index, target, decomposition, noise, rng) {
      Ok(row) =>
        for level in 0..<level_count {
          let ciphertext = row[level].flat_u32_copy()
          let offset = (index * level_count + level) * ciphertext_size
          for word in 0..<ciphertext_size {
            data[offset + word] = ciphertext[word]
          }
        }
      Err(_) => return Err(CiphertextError)
    }
  }
  Ok({
    input_parameters: input.parameters(),
    output_parameters: target.parameters(),
    decomposition,
    data,
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
  let ciphertext_size = self.output_parameters.value() + 1
  let digits = FixedArray::make(self.decomposition.level(), 0)
  let result = FixedArray::make(ciphertext_size, 0U)
  match self.apply_into(ciphertext, result, digits) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match @lwe.lwe_ciphertext_from_flat_u32(self.output_parameters, result) {
    Ok(value) => Ok(value)
    Err(_) => Err(CiphertextError)
  }
}

///|
pub fn KeySwitchKey::apply_into(
  self : KeySwitchKey,
  ciphertext : @lwe.LweCiphertext,
  result : FixedArray[UInt],
  digits : FixedArray[Int],
) -> Result[Unit, KeySwitchError] {
  if ciphertext.parameters() != self.input_parameters {
    return Err(InvalidInputDimension)
  }
  let ciphertext_size = self.output_parameters.value() + 1
  if result.length() != ciphertext_size ||
    digits.length() != self.decomposition.level() {
    return Err(CiphertextError)
  }
  result.fill(0U)
  result[self.output_parameters.value()] = ciphertext.b().to_uint()
  for index in 0..<self.input_parameters.value() {
    let coefficient = match ciphertext.mask_at(index) {
      Ok(value) => value
      Err(_) => return Err(CiphertextError)
    }
    match
      signed_gadget_decompose_into(coefficient, self.decomposition, digits) {
      Ok(_) => ()
      Err(_) => return Err(InvalidDecomposition)
    }
    for level in 0..<digits.length() {
      let offset = (index * self.decomposition.level() + level) *
        ciphertext_size
      let digit = digits[level]
      if digit != 0 {
        for word in 0..<ciphertext_size {
          result[word] = @torus.Torus32::from_uint(result[word])
            .sub(
              @torus.Torus32::from_uint(self.data[offset + word]).scale(digit),
            )
            .to_uint()
        }
      }
    }
  }
  Ok(())
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
test "keyswitch: allocation-free gadget decomposition matches reference" {
  let parameters = @params.decomposition_parameters(7, 4).unwrap()
  let values = [0U, 1U, 0x3FFF_FFFFU, 0x8000_0000U, 0xFFFF_FFFFU]
  let output = FixedArray::make(parameters.level(), 0)
  for value in values {
    let expected = signed_gadget_decompose(
      @torus.Torus32::from_uint(value),
      parameters,
    ).unwrap()
    signed_gadget_decompose_into(
      @torus.Torus32::from_uint(value),
      parameters,
      output,
    ).unwrap()
    for index in 0..<output.length() {
      assert_eq(output[index], expected[index])
    }
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
