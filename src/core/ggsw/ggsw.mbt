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
  ParameterMismatch
  EncryptionFailure
  ExternalProductFailure
} derive(Debug, Eq)

///|
/// A GGSW ciphertext stores (k+1)*level GLWE ciphertext rows. Each GLWE row
/// already contains its (k+1) polynomial columns, so no second GLWE array is
/// nested here.
pub struct GgswCiphertext {
  parameters : GgswParameters
  rows : Array[@glwe.GlweCiphertext]
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
  {
    parameters,
    rows: Array::makei(row_count, fn(_) {
      @glwe.glwe_zero_ciphertext(parameters.glwe)
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
  for ciphertext in self.rows {
    if ciphertext.parameters() != self.parameters.glwe {
      return Err(ShapeMismatch)
    }
  }
  Ok(())
}

///|
/// Encrypt a Boolean control value as a standard GGSW diagonal gadget matrix.
pub fn ggsw_encrypt_boolean(
  parameters : GgswParameters,
  key : @glwe.GlweSecretKey,
  message : Bool,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[GgswCiphertext, GgswError] {
  if key.parameters() != parameters.glwe {
    return Err(ParameterMismatch)
  }
  let n = parameters.glwe.polynomial_size()
  let zero = Array::make(n, @torus.Torus32::zero())
  let rows : Array[@glwe.GlweCiphertext] = []
  for level_index in 0..<parameters.level {
    let shift = 32 - parameters.base_log * (level_index + 1)
    let gadget = @torus.Torus32::from_uint(1U << shift)
    for component in 0..<parameters.columns() {
      let row = match key.encrypt(zero, noise, rng) {
        Ok(value) => value
        Err(_) => return Err(EncryptionFailure)
      }
      if message {
        match row.add_gadget_to_component(component, gadget) {
          Ok(value) => rows.push(value)
          Err(_) => return Err(EncryptionFailure)
        }
      } else {
        rows.push(row)
      }
    }
  }
  Ok({ parameters, rows })
}

///|
/// Compute the external product without access to the GLWE secret key.
pub fn GgswCiphertext::external_product(
  self : GgswCiphertext,
  input : @glwe.GlweCiphertext,
) -> Result[@glwe.GlweCiphertext, GgswError] {
  if self.validate() is Err(_) || input.parameters() != self.parameters.glwe {
    return Err(ParameterMismatch)
  }
  let decomposition = match
    @params.decomposition_parameters(
      self.parameters.base_log,
      self.parameters.level,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidDecomposition)
  }
  let n = self.parameters.glwe.polynomial_size()
  let columns = self.parameters.columns()
  let mut result = @glwe.glwe_zero_ciphertext(self.parameters.glwe)
  for component in 0..<columns {
    let input_component = match input.component(component) {
      Ok(value) => value
      Err(_) => return Err(ExternalProductFailure)
    }
    let decomposed : Array[Array[Int]] = []
    for index in 0..<n {
      match
        @keyswitch.signed_gadget_decompose(
          input_component[index],
          decomposition,
        ) {
        Ok(value) => decomposed.push(value)
        Err(_) => return Err(InvalidDecomposition)
      }
    }
    for level_index in 0..<self.parameters.level {
      let digit_polynomial = Array::makei(n, fn(index) {
        @torus.Torus32::from_int(decomposed[index][level_index])
      })
      let row_index = level_index * columns + component
      let product = match
        self.rows[row_index].mul_plain_poly(digit_polynomial) {
        Ok(value) => value
        Err(_) => return Err(ExternalProductFailure)
      }
      result = match result.add(product) {
        Ok(value) => value
        Err(_) => return Err(ExternalProductFailure)
      }
    }
  }
  Ok(result)
}

///|
/// Select `when_true` for an encrypted one and `when_false` for an encrypted zero.
pub fn GgswCiphertext::cmux(
  self : GgswCiphertext,
  when_true : @glwe.GlweCiphertext,
  when_false : @glwe.GlweCiphertext,
) -> Result[@glwe.GlweCiphertext, GgswError] {
  let difference = match when_true.sub(when_false) {
    Ok(value) => value
    Err(_) => return Err(ParameterMismatch)
  }
  let selected = match self.external_product(difference) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match when_false.add(selected) {
    Ok(value) => Ok(value)
    Err(_) => Err(ExternalProductFailure)
  }
}

///|
test "ggsw: matrix shape is explicit and validated" {
  let glwe = @glwe.glwe_parameters(2, 8).unwrap()
  let parameters = ggsw_parameters(glwe, 4, 8).unwrap()
  let ciphertext = ggsw_zero(parameters)
  assert_eq(parameters.rows(), 24)
  assert_eq(parameters.columns(), 3)
  assert_true(ciphertext.validate() is Ok(_))
}

///|
test "ggsw: encrypted Boolean external product and CMUX preserve plaintext" {
  let glwe = @glwe.glwe_parameters(1, 8).unwrap()
  let key_rng = @random.test_rng_new(0x474753574B4559)
  let key = @glwe.glwe_keygen(glwe, key_rng)
  let parameters = ggsw_parameters(glwe, 4, 8).unwrap()
  let noise = @random.gaussian_sigma_3_fixture()
  let encrypted_zero = ggsw_encrypt_boolean(
    parameters,
    key,
    false,
    noise,
    @random.test_rng_new(0x4747535730),
  ).unwrap()
  let encrypted_one = ggsw_encrypt_boolean(
    parameters,
    key,
    true,
    noise,
    @random.test_rng_new(0x4747535731),
  ).unwrap()
  let amplitude = @torus.Torus32::from_int(0x2000_0000)
  let true_message = Array::makei(8, fn(index) {
    if index == 0 {
      amplitude
    } else {
      @torus.Torus32::zero()
    }
  })
  let false_message = Array::makei(8, fn(index) {
    if index == 0 {
      amplitude.neg()
    } else {
      @torus.Torus32::zero()
    }
  })
  let true_ct = @glwe.glwe_trivial(glwe, true_message).unwrap()
  let false_ct = @glwe.glwe_trivial(glwe, false_message).unwrap()
  let selected_true = key
    .decrypt(encrypted_one.cmux(true_ct, false_ct).unwrap())
    .unwrap()
  let selected_false = key
    .decrypt(encrypted_zero.cmux(true_ct, false_ct).unwrap())
    .unwrap()
  assert_true(selected_true[0].decode_sign())
  assert_true(!selected_false[0].decode_sign())
}
