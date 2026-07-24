///|
pub struct GgswParameters {
  glwe : @glwe.GlweParameters
  base_log : Int
  level : Int
} derive(Debug, Eq)

///|
pub suberror GgswError {
  InvalidDecomposition
  ShapeMismatch
} derive(Debug, Eq)

///|
/// A GGSW ciphertext is a (k+1)*level by (k+1) GLWE matrix.
pub struct GgswCiphertext {
  parameters : GgswParameters
  rows : Array[Array[@glwe.GlweCiphertext]]
}

///|
pub fn ggsw_parameters(
  glwe : @glwe.GlweParameters,
  base_log : Int,
  level : Int,
) -> Result[GgswParameters, GgswError] {
  if base_log <= 0 || level <= 0 || base_log * level > 32 {
    return Err(InvalidDecomposition)
  }
  Ok({ glwe, base_log, level })
}

///|
pub fn GgswParameters::rows(self : GgswParameters) -> Int {
  (self.glwe.glwe_dimension() + 1) * self.level
}

///|
pub fn GgswParameters::columns(self : GgswParameters) -> Int {
  self.glwe.glwe_dimension() + 1
}

///|
pub fn GgswParameters::base_log(self : GgswParameters) -> Int {
  self.base_log
}

///|
pub fn GgswParameters::level(self : GgswParameters) -> Int {
  self.level
}

///|
pub fn GgswParameters::glwe(self : GgswParameters) -> @glwe.GlweParameters {
  self.glwe
}

///|
/// Construct a zero matrix with the exact standard GGSW shape. Encryption and
/// gadget filling are intentionally separate operations so shape validation is
/// independent from the cryptographic implementation.
pub fn ggsw_zero(parameters : GgswParameters) -> GgswCiphertext {
  let row_count = parameters.rows()
  let column_count = parameters.columns()
  {
    parameters,
    rows: Array::makei(row_count, fn(_) {
      Array::makei(column_count, fn(_) {
        @glwe.glwe_zero_ciphertext(parameters.glwe)
      })
    }),
  }
}

///|
pub fn GgswCiphertext::validate(
  self : GgswCiphertext,
) -> Result[Unit, GgswError] {
  if self.rows.length() != self.parameters.rows() {
    return Err(ShapeMismatch)
  }
  for row in self.rows {
    if row.length() != self.parameters.columns() {
      return Err(ShapeMismatch)
    }
    for ciphertext in row {
      if ciphertext.parameters() != self.parameters.glwe {
        return Err(ShapeMismatch)
      }
    }
  }
  Ok(())
}

///|
test "ggsw: matrix shape is explicit and validated" {
  let glwe = @glwe.glwe_parameters(2, 8).unwrap()
  let parameters = ggsw_parameters(glwe, 4, 8).unwrap()
  let ciphertext = ggsw_zero(parameters)
  assert_eq(parameters.rows(), 24)
  assert_true(ciphertext.validate() is Ok(_))
}
