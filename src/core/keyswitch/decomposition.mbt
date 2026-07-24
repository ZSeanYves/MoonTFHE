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
  if parameters.base_log() * parameters.level() < 32 && remaining != 0U {
    return Err(InsufficientLevels)
  }
  Ok(digits)
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
    let digits = signed_decompose(@torus.Torus32::from_uint(value), parameters).unwrap()
    let reconstructed = signed_recompose(digits, parameters).unwrap()
    assert_eq(reconstructed.to_uint(), value)
  }
}

///|
test "keyswitch: insufficient levels are explicit" {
  let parameters = @params.decomposition_parameters(10, 2).unwrap()
  assert_true(
    signed_decompose(@torus.Torus32::from_uint(0xFFFF_FFFFU), parameters)
    is Err(InsufficientLevels),
  )
}
