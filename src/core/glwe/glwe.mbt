///|
pub struct GlweParameters {
  glwe_dimension : Int
  polynomial_size : Int
} derive(Debug, Eq)

///|
pub suberror GlweError {
  InvalidDimension
  InvalidPolynomialSize
  MessageLengthMismatch
  CiphertextShapeMismatch
  NoiseFailure
  InvalidSampleIndex
  InvalidSampleDimension
} derive(Debug, Eq)

///|
pub struct GlweSecretKey {
  parameters : GlweParameters
  data : Array[Array[Bool]]
}

///|
pub struct GlweCiphertext {
  parameters : GlweParameters
  a : Array[Array[@torus.Torus32]]
  b : Array[@torus.Torus32]
}

///|
pub fn glwe_parameters(
  glwe_dimension : Int,
  polynomial_size : Int,
) -> Result[GlweParameters, GlweError] {
  if glwe_dimension <= 0 {
    return Err(InvalidDimension)
  }
  if polynomial_size <= 0 || (polynomial_size & (polynomial_size - 1)) != 0 {
    return Err(InvalidPolynomialSize)
  }
  Ok({ glwe_dimension, polynomial_size })
}

///|
pub fn GlweParameters::glwe_dimension(self : GlweParameters) -> Int {
  self.glwe_dimension
}

///|
pub fn GlweParameters::polynomial_size(self : GlweParameters) -> Int {
  self.polynomial_size
}

///|
pub fn GlweCiphertext::parameters(self : GlweCiphertext) -> GlweParameters {
  self.parameters
}

///|
/// Extract one coefficient into an LWE ciphertext using the standard GLWE
/// negacyclic sign rule. The coefficient index is checked before any access.
pub fn GlweCiphertext::sample_extract(
  self : GlweCiphertext,
  index : Int,
) -> Result[@lwe.LweCiphertext, GlweError] {
  let n = self.parameters.polynomial_size
  if index < 0 || index >= n {
    return Err(InvalidSampleIndex)
  }
  let dimension = self.parameters.glwe_dimension * n
  let lwe_dimension = match @params.lwe_dimension(dimension) {
    Ok(value) => value
    Err(_) => return Err(InvalidSampleDimension)
  }
  let a = Array::makei(dimension, fn(flat_index) {
    let component = flat_index / n
    let coefficient = flat_index % n
    let source = index - coefficient
    if source >= 0 {
      self.a[component][source]
    } else {
      self.a[component][source + n].neg()
    }
  })
  match @lwe.lwe_ciphertext_from_parts(lwe_dimension, a, self.b[index]) {
    Ok(ciphertext) => Ok(ciphertext)
    Err(_) => Err(InvalidSampleDimension)
  }
}

///|
pub fn glwe_zero_ciphertext(parameters : GlweParameters) -> GlweCiphertext {
  let n = parameters.polynomial_size
  {
    parameters,
    a: Array::makei(parameters.glwe_dimension, fn(_) {
      Array::make(n, @torus.Torus32::zero())
    }),
    b: Array::make(n, @torus.Torus32::zero()),
  }
}

///|
pub fn glwe_keygen(
  parameters : GlweParameters,
  rng : @random.RandomGenerator,
) -> GlweSecretKey {
  let data = Array::makei(parameters.glwe_dimension, fn(_) {
    Array::makei(parameters.polynomial_size, fn(_) {
      (rng.next_u32() & 1U) == 1U
    })
  })
  { parameters, data }
}

///|
fn poly_add(
  left : Array[@torus.Torus32],
  right : Array[@torus.Torus32],
) -> Array[@torus.Torus32] {
  Array::makei(left.length(), fn(i) { left[i].add(right[i]) })
}

///|
pub fn GlweSecretKey::encrypt(
  self : GlweSecretKey,
  message : Array[@torus.Torus32],
  noise_distribution : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[GlweCiphertext, GlweError] {
  let n = self.parameters.polynomial_size
  if message.length() != n {
    return Err(MessageLengthMismatch)
  }
  let a = Array::makei(self.parameters.glwe_dimension, fn(_) {
    Array::makei(n, fn(_) {
      @torus.Torus32::from_int(rng.next_u32().reinterpret_as_int())
    })
  })
  let mut body = message.copy()
  for i in 0..<self.parameters.glwe_dimension {
    let product = @polynomial.negacyclic_mul_reference(
      a[i],
      Array::makei(n, fn(j) {
        if self.data[i][j] {
          @torus.Torus32::from_int(1)
        } else {
          @torus.Torus32::zero()
        }
      }),
    ).unwrap()
    body = poly_add(body, product)
  }
  for i in 0..<n {
    let noise = match rng.sample_discrete_gaussian_fixed(noise_distribution) {
      Ok(value) => value
      Err(_) => return Err(NoiseFailure)
    }
    body[i] = body[i].add(@torus.Torus32::from_int(noise))
  }
  Ok({ parameters: self.parameters, a, b: body })
}

///|
pub fn GlweSecretKey::decrypt(
  self : GlweSecretKey,
  ciphertext : GlweCiphertext,
) -> Result[Array[@torus.Torus32], GlweError] {
  if ciphertext.parameters != self.parameters ||
    ciphertext.a.length() != self.parameters.glwe_dimension ||
    ciphertext.b.length() != self.parameters.polynomial_size {
    return Err(CiphertextShapeMismatch)
  }
  let body = ciphertext.b.copy()
  let n = self.parameters.polynomial_size
  for i in 0..<self.parameters.glwe_dimension {
    let product = @polynomial.negacyclic_mul_reference(
      ciphertext.a[i],
      Array::makei(n, fn(j) {
        if self.data[i][j] {
          @torus.Torus32::from_int(1)
        } else {
          @torus.Torus32::zero()
        }
      }),
    ).unwrap()
    for j in 0..<n {
      body[j] = body[j].sub(product[j])
    }
  }
  Ok(body)
}

///|
pub fn GlweCiphertext::add(
  self : GlweCiphertext,
  other : GlweCiphertext,
) -> Result[GlweCiphertext, GlweError] {
  if self.parameters != other.parameters {
    return Err(CiphertextShapeMismatch)
  }
  let a = Array::makei(self.a.length(), fn(i) {
    poly_add(self.a[i], other.a[i])
  })
  Ok({ parameters: self.parameters, a, b: poly_add(self.b, other.b) })
}

///|
pub fn GlweCiphertext::sub(
  self : GlweCiphertext,
  other : GlweCiphertext,
) -> Result[GlweCiphertext, GlweError] {
  if self.parameters != other.parameters {
    return Err(CiphertextShapeMismatch)
  }
  let a = Array::makei(self.a.length(), fn(i) {
    Array::makei(self.a[i].length(), fn(j) { self.a[i][j].sub(other.a[i][j]) })
  })
  let b = Array::makei(self.b.length(), fn(i) { self.b[i].sub(other.b[i]) })
  Ok({ parameters: self.parameters, a, b })
}

///|
test "glwe: explicit dimension and polynomial shape round trip" {
  let parameters = glwe_parameters(2, 4).unwrap()
  let rng = @random.test_rng_new(0x474C5745)
  let key = glwe_keygen(parameters, rng)
  let message = [
    @torus.Torus32::from_int(1),
    @torus.Torus32::from_int(-2),
    @torus.Torus32::from_int(3),
    @torus.Torus32::from_int(-4),
  ]
  let ciphertext = key
    .encrypt(message, @random.gaussian_sigma_3_fixture(), rng)
    .unwrap()
  let decoded = key.decrypt(ciphertext).unwrap()
  for i in 0..<message.length() {
    let error = decoded[i].sub(message[i]).to_int()
    assert_true(error >= -24 && error <= 24)
  }
}

///|
test "glwe: sample extraction handles k=0 and negacyclic wrap" {
  let parameters = glwe_parameters(1, 4).unwrap()
  let ciphertext : GlweCiphertext = {
    parameters,
    a: [
      [
        @torus.Torus32::from_int(1),
        @torus.Torus32::from_int(2),
        @torus.Torus32::from_int(3),
        @torus.Torus32::from_int(4),
      ],
    ],
    b: [
      @torus.Torus32::from_int(10),
      @torus.Torus32::from_int(11),
      @torus.Torus32::from_int(12),
      @torus.Torus32::from_int(13),
    ],
  }
  let extracted = ciphertext.sample_extract(0).unwrap()
  assert_eq(extracted.a().map(fn(value) { value.to_int() }), [1, -4, -3, -2])
  assert_eq(extracted.b().to_int(), 10)
  assert_true(ciphertext.sample_extract(4) is Err(InvalidSampleIndex))
}
