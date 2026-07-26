///|
/// Checked contiguous layouts used by the PBS workspace and native boundary.
pub suberror PackedShapeError {
  InvalidShape
  Overflow
} derive(Debug, Eq)

///|
pub struct PackedLwe {
  dimension : @params.LweDimension
  data : FixedArray[UInt]
}

///|
pub struct PackedGlwe {
  parameters : @glwe.GlweParameters
  data : FixedArray[UInt]
}

///|
pub struct PackedGgsw {
  parameters : @ggsw.GgswParameters
  data : FixedArray[UInt]
}

///|
pub struct PackedKeySwitchKey {
  input_dimension : @params.LweDimension
  output_dimension : @params.LweDimension
  decomposition : @params.DecompositionParameters
  data : FixedArray[UInt]
}

///|
fn packed_mul(left : Int, right : Int) -> Result[Int, PackedShapeError] {
  if left < 0 || right < 0 || (right != 0 && left > 2_000_000_000 / right) {
    Err(Overflow)
  } else {
    Ok(left * right)
  }
}

///|
pub fn packed_lwe_new(
  dimension : @params.LweDimension,
) -> Result[PackedLwe, PackedShapeError] {
  Ok({ dimension, data: FixedArray::make(dimension.value() + 1, 0U) })
}

///|
pub fn packed_glwe_new(
  parameters : @glwe.GlweParameters,
) -> Result[PackedGlwe, PackedShapeError] {
  let length = match
    packed_mul(parameters.glwe_dimension() + 1, parameters.polynomial_size()) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ parameters, data: FixedArray::make(length, 0U) })
}

///|
pub fn packed_ggsw_new(
  parameters : @ggsw.GgswParameters,
) -> Result[PackedGgsw, PackedShapeError] {
  let length = match
    packed_mul(
      parameters.rows(),
      parameters.columns() * parameters.glwe().polynomial_size(),
    ) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ parameters, data: FixedArray::make(length, 0U) })
}

///|
pub fn packed_key_switch_new(
  input_dimension : @params.LweDimension,
  output_dimension : @params.LweDimension,
  decomposition : @params.DecompositionParameters,
) -> Result[PackedKeySwitchKey, PackedShapeError] {
  if decomposition.base_log() <= 0 || decomposition.level() <= 0 {
    return Err(InvalidShape)
  }
  let rows = match packed_mul(input_dimension.value(), decomposition.level()) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let length = match packed_mul(rows, output_dimension.value() + 1) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({
    input_dimension,
    output_dimension,
    decomposition,
    data: FixedArray::make(length, 0U),
  })
}

///|
pub fn PackedLwe::word_length(self : PackedLwe) -> Int {
  self.data.length()
}

///|
pub fn PackedGlwe::word_length(self : PackedGlwe) -> Int {
  self.data.length()
}

///|
pub fn PackedGgsw::word_length(self : PackedGgsw) -> Int {
  self.data.length()
}

///|
pub fn PackedKeySwitchKey::word_length(self : PackedKeySwitchKey) -> Int {
  self.data.length()
}

///|
test "packed layouts use checked contiguous lengths" {
  assert_eq(
    packed_lwe_new(@params.lwe_dimension(3).unwrap()).unwrap().word_length(),
    4,
  )
  let glwe = @glwe.glwe_parameters(1, 8).unwrap()
  assert_eq(packed_glwe_new(glwe).unwrap().word_length(), 16)
  let ggsw = @ggsw.ggsw_parameters(glwe, 2, 3).unwrap()
  assert_eq(packed_ggsw_new(ggsw).unwrap().word_length(), ggsw.flat_size())
  assert_eq(
    packed_key_switch_new(
      @params.lwe_dimension(3).unwrap(),
      @params.lwe_dimension(5).unwrap(),
      @params.decomposition_parameters(2, 3).unwrap(),
    )
    .unwrap()
    .word_length(),
    54,
  )
}
