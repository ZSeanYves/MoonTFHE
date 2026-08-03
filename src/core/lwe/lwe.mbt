///|
pub struct LweSecretKey {
  parameters : @params.LweDimension
  bits : FixedArray[UInt]
}

///|
pub struct LweCiphertext {
  parameters : @params.LweDimension
  data : FixedArray[UInt]
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
  { parameters, bits: FixedArray::makei(n, fn(_) { rng.next_u32() & 1U }) }
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
  Ok({
    parameters,
    bits: FixedArray::makei(bits.length(), fn(index) {
      if bits[index] {
        1U
      } else {
        0U
      }
    }),
  })
}

///|
/// Construct a binary LWE key from caller-owned material. This is intended
/// for key-generation code that keeps the material local; the secret bits are
/// never exposed through an accessor on the key type.
pub fn lwe_key_from_binary_secret_unchecked(
  parameters : @params.LweDimension,
  bits : Array[Bool],
) -> LweSecretKey {
  {
    parameters,
    bits: FixedArray::makei(bits.length(), fn(index) {
      if bits[index] {
        1U
      } else {
        0U
      }
    }),
  }
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
    Ok({
      parameters,
      data: FixedArray::makei(a.length() + 1, fn(index) {
        if index == a.length() {
          b.to_uint()
        } else {
          a[index].to_uint()
        }
      }),
    })
  }
}

///|
/// Construct an LWE ciphertext from the canonical `(mask || body)` layout.
pub fn lwe_ciphertext_from_flat_u32(
  parameters : @params.LweDimension,
  data : FixedArray[UInt],
) -> Result[LweCiphertext, LweError] {
  if data.length() != parameters.value() + 1 {
    Err(CiphertextDimensionMismatch)
  } else {
    Ok({ parameters, data: data.copy() })
  }
}

///|
pub fn LweCiphertext::mask_at(
  self : LweCiphertext,
  index : Int,
) -> Result[@torus.Torus32, LweError] {
  if index < 0 || index >= self.parameters.value() {
    Err(InvalidIndex)
  } else {
    Ok(@torus.Torus32::from_uint(self.data[index]))
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
  self.lwe_encrypt_torus_with_streams(encoded, noise, rng, rng)
}

///|
pub fn LweSecretKey::lwe_encrypt_torus(
  self : LweSecretKey,
  message : @torus.Torus32,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
) -> Result[LweCiphertext, LweError] {
  self.lwe_encrypt_torus_with_streams(message, noise, rng, rng)
}

///|
/// Encrypt using independently domain-separated mask and noise streams.
pub fn LweSecretKey::lwe_encrypt_torus_with_streams(
  self : LweSecretKey,
  message : @torus.Torus32,
  noise : @random.DiscreteGaussian,
  mask_rng : @random.RandomGenerator,
  noise_rng : @random.RandomGenerator,
) -> Result[LweCiphertext, LweError] {
  let n = self.parameters.value()
  let data = FixedArray::make(n + 1, 0U)
  let mut phase = message
  for i in 0..<n {
    data[i] = mask_rng.next_u32()
    if self.bits[i] == 1U {
      phase = phase.add(@torus.Torus32::from_uint(data[i]))
    }
  }
  let error = match noise_rng.sample_discrete_gaussian_fixed(noise) {
    Ok(value) => value
    Err(_) => return Err(NoiseFailure)
  }
  data[n] = phase.add(@torus.Torus32::from_int(error)).to_uint()
  Ok({ parameters: self.parameters, data })
}

///|
pub fn lwe_trivial(
  parameters : @params.LweDimension,
  message : @torus.Torus32,
) -> LweCiphertext {
  let data = FixedArray::make(parameters.value() + 1, 0U)
  data[parameters.value()] = message.to_uint()
  { parameters, data }
}

///|
pub fn LweCiphertext::sub_scaled(
  self : LweCiphertext,
  other : LweCiphertext,
  scalar : Int,
) -> Result[LweCiphertext, LweError] {
  if self.parameters != other.parameters ||
    self.data.length() != other.data.length() {
    return Err(CiphertextDimensionMismatch)
  }
  Ok({
    parameters: self.parameters,
    data: FixedArray::makei(self.data.length(), fn(index) {
      @torus.Torus32::from_uint(self.data[index])
      .sub(@torus.Torus32::from_uint(other.data[index]).scale(scalar))
      .to_uint()
    }),
  })
}

///|
/// Add two LWE ciphertexts in the same secret-key domain.
pub fn LweCiphertext::add(
  self : LweCiphertext,
  other : LweCiphertext,
) -> Result[LweCiphertext, LweError] {
  if self.parameters != other.parameters ||
    self.data.length() != other.data.length() {
    return Err(CiphertextDimensionMismatch)
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
/// Negate every coefficient modulo the native Torus32 modulus.
pub fn LweCiphertext::neg(self : LweCiphertext) -> LweCiphertext {
  {
    parameters: self.parameters,
    data: FixedArray::makei(self.data.length(), fn(index) {
      @torus.Torus32::from_uint(self.data[index]).neg().to_uint()
    }),
  }
}

///|
/// Add a public torus constant to the body of an LWE ciphertext.
pub fn LweCiphertext::add_plain(
  self : LweCiphertext,
  value : @torus.Torus32,
) -> LweCiphertext {
  let data = self.data.copy()
  let body = self.parameters.value()
  data[body] = @torus.Torus32::from_uint(data[body]).add(value).to_uint()
  { parameters: self.parameters, data }
}

///|
/// Subtract a public torus constant from the body of an LWE ciphertext.
pub fn LweCiphertext::sub_plain(
  self : LweCiphertext,
  value : @torus.Torus32,
) -> LweCiphertext {
  let data = self.data.copy()
  let body = self.parameters.value()
  data[body] = @torus.Torus32::from_uint(data[body]).sub(value).to_uint()
  { parameters: self.parameters, data }
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
    let plaintext = if self.bits[index] == 1U {
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
/// Encrypt one secret gadget row directly into a caller-owned packed KSK.
pub fn LweSecretKey::encrypt_secret_gadget_row_into(
  self : LweSecretKey,
  index : Int,
  target : LweSecretKey,
  decomposition : @params.DecompositionParameters,
  noise : @random.DiscreteGaussian,
  rng : @random.RandomGenerator,
  output : FixedArray[UInt],
  output_offset : Int,
) -> Result[Unit, LweError] {
  if index < 0 || index >= self.bits.length() {
    return Err(InvalidIndex)
  }
  let base_log = decomposition.base_log()
  let level_count = decomposition.level()
  if base_log <= 0 || level_count <= 0 || base_log * level_count > 32 {
    return Err(InvalidDecomposition)
  }
  let ciphertext_size = target.parameters.value() + 1
  let row_size = level_count * ciphertext_size
  if output_offset < 0 ||
    output.length() < row_size ||
    output_offset > output.length() - row_size {
    return Err(CiphertextDimensionMismatch)
  }
  for level_index in 0..<level_count {
    let shift = 32 - base_log * (level_index + 1)
    let gadget = 1U << shift
    let mut phase = if self.bits[index] == 1U {
      @torus.Torus32::from_uint(gadget)
    } else {
      @torus.Torus32::zero()
    }
    let ciphertext_offset = output_offset + level_index * ciphertext_size
    for coefficient in 0..<target.parameters.value() {
      let mask = rng.next_u32()
      output[ciphertext_offset + coefficient] = mask
      if target.bits[coefficient] == 1U {
        phase = phase.add(@torus.Torus32::from_uint(mask))
      }
    }
    let error = match rng.sample_discrete_gaussian_fixed(noise) {
      Ok(value) => value
      Err(_) => return Err(NoiseFailure)
    }
    output[ciphertext_offset + target.parameters.value()] = phase
      .add(@torus.Torus32::from_int(error))
      .to_uint()
  }
  Ok(())
}

///|
pub fn LweSecretKey::parameters(self : LweSecretKey) -> @params.LweDimension {
  self.parameters
}

///|
/// Pack the binary secret for an explicit authenticated SecretExport flow.
/// High-level APIs must encrypt this payload immediately and must not expose it
/// as their default serialization format.
pub fn LweSecretKey::secret_export_payload(self : LweSecretKey) -> Bytes {
  let output = Array::make(9 + (self.bits.length() + 7) / 8, b'\x00')
  output[0] = b'M'
  output[1] = b'S'
  output[2] = b'C'
  output[3] = b'R'
  output[4] = b'\x01'
  let length = self.bits.length().reinterpret_as_uint()
  output[5] = length.to_byte()
  output[6] = (length >> 8).to_byte()
  output[7] = (length >> 16).to_byte()
  output[8] = (length >> 24).to_byte()
  for index in 0..<self.bits.length() {
    if self.bits[index] == 1U {
      let byte_index = 9 + index / 8
      output[byte_index] = output[byte_index] | (1U << (index % 8)).to_byte()
    }
  }
  Bytes::from_array(output)
}

///|
pub fn LweSecretKey::lwe_decrypt_binary(
  self : LweSecretKey,
  ciphertext : LweCiphertext,
) -> Result[Bool, LweError] {
  if ciphertext.parameters != self.parameters ||
    ciphertext.data.length() != self.bits.length() + 1 {
    return Err(CiphertextDimensionMismatch)
  }
  let mut phase = @torus.Torus32::from_uint(ciphertext.data[self.bits.length()])
  for i in 0..<self.bits.length() {
    if self.bits[i] == 1U {
      phase = phase.sub(@torus.Torus32::from_uint(ciphertext.data[i]))
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
  Array::makei(self.parameters.value(), fn(index) {
    @torus.Torus32::from_uint(self.data[index])
  })
}

///|
pub fn LweCiphertext::b(self : LweCiphertext) -> @torus.Torus32 {
  @torus.Torus32::from_uint(self.data[self.parameters.value()])
}

///|
/// Copy the canonical `(mask || body)` representation.
pub fn LweCiphertext::flat_u32_copy(self : LweCiphertext) -> FixedArray[UInt] {
  self.data.copy()
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

///|
test "lwe core: coefficient negation flips Boolean encoding" {
  let dimension = @params.lwe_dimension(32).unwrap()
  let key = lwe_keygen(dimension, @random.test_rng_new(0x4C57454E4547))
  let ciphertext = key
    .lwe_encrypt_binary(
      true,
      @random.gaussian_sigma_3_fixture(),
      @random.test_rng_new(8),
    )
    .unwrap()
  assert_eq(key.lwe_decrypt_binary(ciphertext.neg()), Ok(false))
}
