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
  InvalidComponent
  PolynomialFailure
} derive(Debug, Eq)

///|
pub struct GlweSecretKey {
  parameters : GlweParameters
  data : FixedArray[UInt]
}

///|
pub struct GlweCiphertext {
  parameters : GlweParameters
  data : FixedArray[UInt]
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
pub fn GlweSecretKey::parameters(self : GlweSecretKey) -> GlweParameters {
  self.parameters
}

///|
pub fn GlweCiphertext::component(
  self : GlweCiphertext,
  index : Int,
) -> Result[Array[@torus.Torus32], GlweError] {
  if index < 0 || index > self.parameters.glwe_dimension {
    return Err(InvalidComponent)
  }
  let n = self.parameters.polynomial_size
  let offset = index * n
  Ok(
    Array::makei(n, fn(coefficient) {
      @torus.Torus32::from_uint(self.data[offset + coefficient])
    }),
  )
}

///|
/// Construct a GLWE ciphertext from `(mask polynomials || body polynomial)`.
pub fn glwe_ciphertext_from_flat_u32(
  parameters : GlweParameters,
  data : FixedArray[UInt],
) -> Result[GlweCiphertext, GlweError] {
  let expected = (parameters.glwe_dimension + 1) * parameters.polynomial_size
  if data.length() != expected {
    Err(CiphertextShapeMismatch)
  } else {
    Ok({ parameters, data: data.copy() })
  }
}

///|
/// Adopt a validated caller-owned flat buffer without copying it. This is an
/// internal core boundary used by preallocated native PBS workspaces.
pub fn glwe_ciphertext_from_owned_flat_u32(
  parameters : GlweParameters,
  data : FixedArray[UInt],
) -> Result[GlweCiphertext, GlweError] {
  let expected = (parameters.glwe_dimension + 1) * parameters.polynomial_size
  if data.length() != expected {
    Err(CiphertextShapeMismatch)
  } else {
    Ok({ parameters, data })
  }
}

///|
pub fn GlweCiphertext::flat_u32_copy(self : GlweCiphertext) -> FixedArray[UInt] {
  self.data.copy()
}

///|
pub fn GlweCiphertext::word_at(
  self : GlweCiphertext,
  index : Int,
) -> Result[UInt, GlweError] {
  if index < 0 || index >= self.data.length() {
    Err(CiphertextShapeMismatch)
  } else {
    Ok(self.data[index])
  }
}

///|
pub fn glwe_trivial(
  parameters : GlweParameters,
  message : Array[@torus.Torus32],
) -> Result[GlweCiphertext, GlweError] {
  if message.length() != parameters.polynomial_size {
    return Err(MessageLengthMismatch)
  }
  let n = parameters.polynomial_size
  let body_offset = parameters.glwe_dimension * n
  let data = FixedArray::make((parameters.glwe_dimension + 1) * n, 0U)
  for index in 0..<n {
    data[body_offset + index] = message[index].to_uint()
  }
  Ok({ parameters, data })
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
  let data = FixedArray::make(dimension + 1, 0U)
  for flat_index in 0..<dimension {
    let component = flat_index / n
    let coefficient = flat_index % n
    let source = index - coefficient
    data[flat_index] = if source >= 0 {
      self.data[component * n + source]
    } else {
      @torus.Torus32::from_uint(self.data[component * n + source + n])
      .neg()
      .to_uint()
    }
  }
  data[dimension] = self.data[dimension + index]
  match @lwe.lwe_ciphertext_from_flat_u32(lwe_dimension, data) {
    Ok(ciphertext) => Ok(ciphertext)
    Err(_) => Err(InvalidSampleDimension)
  }
}

///|
pub fn GlweCiphertext::sample_extract_into(
  self : GlweCiphertext,
  index : Int,
  output : FixedArray[UInt],
) -> Result[Unit, GlweError] {
  let n = self.parameters.polynomial_size
  let dimension = self.parameters.glwe_dimension * n
  if index < 0 || index >= n {
    return Err(InvalidSampleIndex)
  }
  if output.length() != dimension + 1 {
    return Err(InvalidSampleDimension)
  }
  for flat_index in 0..<dimension {
    let component = flat_index / n
    let coefficient = flat_index % n
    let source = index - coefficient
    output[flat_index] = if source >= 0 {
      self.data[component * n + source]
    } else {
      @torus.Torus32::from_uint(self.data[component * n + source + n])
      .neg()
      .to_uint()
    }
  }
  output[dimension] = self.data[dimension + index]
  Ok(())
}

///|
pub fn glwe_zero_ciphertext(parameters : GlweParameters) -> GlweCiphertext {
  {
    parameters,
    data: FixedArray::make(
      (parameters.glwe_dimension + 1) * parameters.polynomial_size,
      0U,
    ),
  }
}

///|
pub fn glwe_keygen(
  parameters : GlweParameters,
  rng : @random.RandomGenerator,
) -> GlweSecretKey {
  let data = FixedArray::makei(
    parameters.glwe_dimension * parameters.polynomial_size,
    fn(_) { rng.next_u32() & 1U },
  )
  { parameters, data }
}

///|
/// Construct a GLWE binary key from local caller-owned material. The shape is
/// checked before the key is created and no secret accessor is provided.
pub fn glwe_key_from_binary_secret(
  parameters : GlweParameters,
  data : Array[Array[Bool]],
) -> Result[GlweSecretKey, GlweError] {
  if data.length() != parameters.glwe_dimension {
    return Err(CiphertextShapeMismatch)
  }
  for component in data {
    if component.length() != parameters.polynomial_size {
      return Err(CiphertextShapeMismatch)
    }
  }
  let n = parameters.polynomial_size
  Ok({
    parameters,
    data: FixedArray::makei(parameters.glwe_dimension * n, fn(index) {
      if data[index / n][index % n] {
        1U
      } else {
        0U
      }
    }),
  })
}

///|
/// Return the LWE key induced by coefficient-wise GLWE sample extraction.
/// The binary secret never crosses the public representation boundary.
pub fn GlweSecretKey::to_extracted_lwe_key(
  self : GlweSecretKey,
) -> Result[@lwe.LweSecretKey, GlweError] {
  let dimension = match
    @params.lwe_dimension(
      self.parameters.glwe_dimension * self.parameters.polynomial_size,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidSampleDimension)
  }
  let bits = Array::makei(self.data.length(), fn(index) {
    self.data[index] == 1U
  })
  match @lwe.lwe_key_from_binary_secret(dimension, bits) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidSampleDimension)
  }
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
  let data = FixedArray::make((self.parameters.glwe_dimension + 1) * n, 0U)
  let body = message.copy()
  for component in 0..<self.parameters.glwe_dimension {
    let mask = Array::makei(n, fn(coefficient) {
      let raw = rng.next_u32()
      data[component * n + coefficient] = raw
      @torus.Torus32::from_uint(raw)
    })
    let product = match
      @polynomial.negacyclic_mul_reference(
        mask,
        Array::makei(n, fn(coefficient) {
          if self.data[component * n + coefficient] == 1U {
            @torus.Torus32::from_int(1)
          } else {
            @torus.Torus32::zero()
          }
        }),
      ) {
      Ok(value) => value
      Err(_) => return Err(PolynomialFailure)
    }
    for coefficient in 0..<n {
      body[coefficient] = body[coefficient].add(product[coefficient])
    }
  }
  for i in 0..<n {
    let noise = match rng.sample_discrete_gaussian_fixed(noise_distribution) {
      Ok(value) => value
      Err(_) => return Err(NoiseFailure)
    }
    body[i] = body[i].add(@torus.Torus32::from_int(noise))
    data[self.parameters.glwe_dimension * n + i] = body[i].to_uint()
  }
  Ok({ parameters: self.parameters, data })
}

///|
/// Encrypt a GLWE row using one preallocated native FFT plan. Masks and noise
/// remain generated in MoonBit; only the batched mask/secret convolution
/// crosses the borrowed-array ABI.
pub fn GlweSecretKey::encrypt_with_fft(
  self : GlweSecretKey,
  message : Array[@torus.Torus32],
  noise_distribution : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
  plan : @provider.FftPlan,
) -> Result[GlweCiphertext, GlweError] {
  let n = self.parameters.polynomial_size
  let k = self.parameters.glwe_dimension
  if message.length() != n {
    return Err(MessageLengthMismatch)
  }
  let masks = FixedArray::make(k * n, 0U)
  for index in 0..<masks.length() {
    masks[index] = rng.next_u32()
  }
  let products = FixedArray::make(n, 0U)
  match plan.batched_glwe_convolution(masks, self.data, k, products) {
    Ok(_) => ()
    Err(_) => return Err(PolynomialFailure)
  }
  let data = FixedArray::make((k + 1) * n, 0U)
  for index in 0..<masks.length() {
    data[index] = masks[index]
  }
  for index in 0..<n {
    let noise = match rng.sample_discrete_gaussian_fixed(noise_distribution) {
      Ok(value) => value
      Err(_) => return Err(NoiseFailure)
    }
    data[k * n + index] = message[index]
      .add(@torus.Torus32::from_uint(products[index]))
      .add(@torus.Torus32::from_int(noise))
      .to_uint()
  }
  Ok({ parameters: self.parameters, data })
}

///|
pub fn GlweSecretKey::decrypt(
  self : GlweSecretKey,
  ciphertext : GlweCiphertext,
) -> Result[Array[@torus.Torus32], GlweError] {
  if ciphertext.parameters != self.parameters ||
    ciphertext.data.length() !=
    (self.parameters.glwe_dimension + 1) * self.parameters.polynomial_size {
    return Err(CiphertextShapeMismatch)
  }
  let n = self.parameters.polynomial_size
  let body_offset = self.parameters.glwe_dimension * n
  let body = Array::makei(n, fn(index) {
    @torus.Torus32::from_uint(ciphertext.data[body_offset + index])
  })
  for component in 0..<self.parameters.glwe_dimension {
    let product = match
      @polynomial.negacyclic_mul_reference(
        Array::makei(n, fn(index) {
          @torus.Torus32::from_uint(ciphertext.data[component * n + index])
        }),
        Array::makei(n, fn(index) {
          if self.data[component * n + index] == 1U {
            @torus.Torus32::from_int(1)
          } else {
            @torus.Torus32::zero()
          }
        }),
      ) {
      Ok(value) => value
      Err(_) => return Err(PolynomialFailure)
    }
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
  Ok({
    parameters: self.parameters,
    data: FixedArray::makei(self.data.length(), fn(index) {
      @torus.Torus32::from_uint(self.data[index])
      .add(@torus.Torus32::from_uint(other.data[index]))
      .to_uint()
    }),
  })
}

///|
pub fn GlweCiphertext::add_into(
  self : GlweCiphertext,
  other : GlweCiphertext,
  output : FixedArray[UInt],
) -> Result[Unit, GlweError] {
  if self.parameters != other.parameters ||
    output.length() != self.data.length() {
    return Err(CiphertextShapeMismatch)
  }
  for index in 0..<self.data.length() {
    output[index] = @torus.Torus32::from_uint(self.data[index])
      .add(@torus.Torus32::from_uint(other.data[index]))
      .to_uint()
  }
  Ok(())
}

///|
pub fn GlweCiphertext::sub(
  self : GlweCiphertext,
  other : GlweCiphertext,
) -> Result[GlweCiphertext, GlweError] {
  if self.parameters != other.parameters {
    return Err(CiphertextShapeMismatch)
  }
  Ok({
    parameters: self.parameters,
    data: FixedArray::makei(self.data.length(), fn(index) {
      @torus.Torus32::from_uint(self.data[index])
      .sub(@torus.Torus32::from_uint(other.data[index]))
      .to_uint()
    }),
  })
}

///|
pub fn GlweCiphertext::sub_into(
  self : GlweCiphertext,
  other : GlweCiphertext,
  output : FixedArray[UInt],
) -> Result[Unit, GlweError] {
  if self.parameters != other.parameters ||
    output.length() != self.data.length() {
    return Err(CiphertextShapeMismatch)
  }
  for index in 0..<self.data.length() {
    output[index] = @torus.Torus32::from_uint(self.data[index])
      .sub(@torus.Torus32::from_uint(other.data[index]))
      .to_uint()
  }
  Ok(())
}

///|
/// Multiply every component by X^rotation in Z[X]/(X^N + 1).
pub fn GlweCiphertext::rotate_negacyclic(
  self : GlweCiphertext,
  rotation : Int,
) -> GlweCiphertext {
  let n = self.parameters.polynomial_size
  let period = 2 * n
  let normalized = (rotation % period + period) % period
  let data = FixedArray::make(self.data.length(), 0U)
  for component in 0..<=self.parameters.glwe_dimension {
    let offset = component * n
    for source in 0..<n {
      let exponent = source + normalized
      let wraps = exponent / n
      let destination = exponent % n
      data[offset + destination] = if (wraps & 1) == 0 {
        self.data[offset + source]
      } else {
        @torus.Torus32::from_uint(self.data[offset + source]).neg().to_uint()
      }
    }
  }
  { parameters: self.parameters, data }
}

///|
pub fn GlweCiphertext::rotate_negacyclic_into(
  self : GlweCiphertext,
  rotation : Int,
  output : FixedArray[UInt],
) -> Result[Unit, GlweError] {
  if output.length() != self.data.length() {
    return Err(CiphertextShapeMismatch)
  }
  let n = self.parameters.polynomial_size
  let period = 2 * n
  let normalized = (rotation % period + period) % period
  for component in 0..<=self.parameters.glwe_dimension {
    let offset = component * n
    for source in 0..<n {
      let exponent = source + normalized
      let wraps = exponent / n
      let destination = exponent % n
      output[offset + destination] = if (wraps & 1) == 0 {
        self.data[offset + source]
      } else {
        @torus.Torus32::from_uint(self.data[offset + source]).neg().to_uint()
      }
    }
  }
  Ok(())
}

///|
/// Add one constant gadget polynomial to a selected GLWE component.
pub fn GlweCiphertext::add_gadget_to_component(
  self : GlweCiphertext,
  component : Int,
  gadget : @torus.Torus32,
) -> Result[GlweCiphertext, GlweError] {
  if component < 0 || component > self.parameters.glwe_dimension {
    return Err(InvalidComponent)
  }
  let data = self.data.copy()
  let offset = component * self.parameters.polynomial_size
  data[offset] = @torus.Torus32::from_uint(data[offset]).add(gadget).to_uint()
  Ok({ parameters: self.parameters, data })
}

///|
/// Multiply every GLWE component by a public polynomial in Z/(2^32)[X]/(X^N+1).
pub fn GlweCiphertext::mul_plain_poly(
  self : GlweCiphertext,
  polynomial : Array[@torus.Torus32],
) -> Result[GlweCiphertext, GlweError] {
  if polynomial.length() != self.parameters.polynomial_size {
    return Err(MessageLengthMismatch)
  }
  let n = self.parameters.polynomial_size
  let data = FixedArray::make(self.data.length(), 0U)
  for component in 0..<=self.parameters.glwe_dimension {
    let offset = component * n
    let product = match
      @polynomial.negacyclic_mul_reference(
        Array::makei(n, fn(index) {
          @torus.Torus32::from_uint(self.data[offset + index])
        }),
        polynomial,
      ) {
      Ok(value) => value
      Err(_) => return Err(MessageLengthMismatch)
    }
    for index in 0..<n {
      data[offset + index] = product[index].to_uint()
    }
  }
  Ok({ parameters: self.parameters, data })
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
  let ciphertext = glwe_ciphertext_from_flat_u32(
    parameters,
    FixedArray::from_array([1U, 2U, 3U, 4U, 10U, 11U, 12U, 13U]),
  ).unwrap()
  let extracted = ciphertext.sample_extract(0).unwrap()
  assert_eq(extracted.a().map(fn(value) { value.to_int() }), [1, -4, -3, -2])
  assert_eq(extracted.b().to_int(), 10)
  assert_true(ciphertext.sample_extract(4) is Err(InvalidSampleIndex))
}
