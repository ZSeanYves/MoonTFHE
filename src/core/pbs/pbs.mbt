///|
pub enum PbsOrder {
  KeyswitchBootstrap
  BootstrapKeyswitch
} derive(Debug, Eq)

///|
/// A fixed two-point Boolean programmable LUT. The full arbitrary torus LUT
/// representation is added with the Fourier BSK backend in C4.
pub struct BooleanLut {
  false_value : @torus.Torus32
  true_value : @torus.Torus32
} derive(Debug, Eq)

///|
pub suberror PbsError {
  InvalidLut
  InvalidPolynomialSize
  InputDimensionMismatch
  BootstrapKeyShapeMismatch
  BlindRotationFailure
  SampleExtractionFailure
  KeyswitchFailure
  UnsupportedOrder
} derive(Debug, Eq)

///|
/// Secret-free bootstrapping material. Construction accepts only encrypted
/// GGSW controls and an encrypted key-switching key.
pub struct BootstrapKey {
  input_dimension : @params.LweDimension
  glwe_parameters : @glwe.GlweParameters
  controls : Array[@ggsw.GgswCiphertext]
  key_switch : @keyswitch.KeySwitchKey
  order : PbsOrder
}

///|
pub fn boolean_lut(
  false_value : @torus.Torus32,
  true_value : @torus.Torus32,
) -> BooleanLut {
  { false_value, true_value }
}

///|
pub fn BooleanLut::evaluate_reference(
  self : BooleanLut,
  input : Bool,
) -> @torus.Torus32 {
  if input {
    self.true_value
  } else {
    self.false_value
  }
}

///|
pub fn BooleanLut::false_value(self : BooleanLut) -> @torus.Torus32 {
  self.false_value
}

///|
pub fn BooleanLut::true_value(self : BooleanLut) -> @torus.Torus32 {
  self.true_value
}

///|
pub fn bootstrap_key_from_encrypted_parts(
  input_dimension : @params.LweDimension,
  glwe_parameters : @glwe.GlweParameters,
  controls : Array[@ggsw.GgswCiphertext],
  key_switch : @keyswitch.KeySwitchKey,
  order : PbsOrder,
) -> Result[BootstrapKey, PbsError] {
  if controls.length() != input_dimension.value() {
    return Err(BootstrapKeyShapeMismatch)
  }
  let extracted_dimension = match
    @params.lwe_dimension(
      glwe_parameters.glwe_dimension() * glwe_parameters.polynomial_size(),
    ) {
    Ok(value) => value
    Err(_) => return Err(BootstrapKeyShapeMismatch)
  }
  if key_switch.input_dimension() != extracted_dimension ||
    key_switch.output_dimension() != input_dimension {
    return Err(BootstrapKeyShapeMismatch)
  }
  for control in controls {
    if control.validate() is Err(_) {
      return Err(BootstrapKeyShapeMismatch)
    }
  }
  Ok({ input_dimension, glwe_parameters, controls, key_switch, order })
}

///|
fn polynomial_log_modulus(size : Int) -> Result[Int, PbsError] {
  if size <= 0 || (size & (size - 1)) != 0 || size > 32768 {
    return Err(InvalidPolynomialSize)
  }
  let mut value = size
  let mut log = 0
  while value > 1 {
    value = value >> 1
    log = log + 1
  }
  Ok(log)
}

///|
fn accumulator_set_output(
  polynomial : Array[@torus.Torus32],
  rotation : Int,
  output : @torus.Torus32,
) -> Unit {
  let n = polynomial.length()
  let period = 2 * n
  let exponent = (period - rotation % period) % period
  if exponent < n {
    polynomial[exponent] = output
  } else {
    polynomial[exponent - n] = output.neg()
  }
}

///|
fn BooleanLut::accumulator(
  self : BooleanLut,
  parameters : @glwe.GlweParameters,
) -> Result[@glwe.GlweCiphertext, PbsError] {
  let n = parameters.polynomial_size()
  let log_n = match polynomial_log_modulus(n) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let modulus = match @torus.CiphertextModulus::power_of_two(log_n + 1) {
    Ok(value) => value
    Err(_) => return Err(InvalidPolynomialSize)
  }
  let positive = match
    @torus.Torus32::from_int(0x2000_0000).modulus_switch(modulus) {
    Ok(value) => value
    Err(_) => return Err(InvalidLut)
  }
  let negative = match
    @torus.Torus32::from_int(-0x2000_0000).modulus_switch(modulus) {
    Ok(value) => value
    Err(_) => return Err(InvalidLut)
  }
  let polynomial = Array::make(n, @torus.Torus32::zero())
  accumulator_set_output(polynomial, positive, self.true_value)
  accumulator_set_output(polynomial, negative, self.false_value)
  match @glwe.glwe_trivial(parameters, polynomial) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidLut)
  }
}

///|
pub fn BootstrapKey::blind_rotate(
  self : BootstrapKey,
  accumulator : @glwe.GlweCiphertext,
  input : @lwe.LweCiphertext,
) -> Result[@glwe.GlweCiphertext, PbsError] {
  if input.parameters() != self.input_dimension ||
    input.a().length() != self.controls.length() ||
    accumulator.parameters() != self.glwe_parameters {
    return Err(InputDimensionMismatch)
  }
  let n = self.glwe_parameters.polynomial_size()
  let log_n = match polynomial_log_modulus(n) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let modulus = match @torus.CiphertextModulus::power_of_two(log_n + 1) {
    Ok(value) => value
    Err(_) => return Err(InvalidPolynomialSize)
  }
  let initial_rotation = match input.b().modulus_switch(modulus) {
    Ok(value) => value
    Err(_) => return Err(BlindRotationFailure)
  }
  let mut result = accumulator.rotate_negacyclic(initial_rotation)
  let mask = input.a()
  for index in 0..<mask.length() {
    let switched = match mask[index].modulus_switch(modulus) {
      Ok(value) => value
      Err(_) => return Err(BlindRotationFailure)
    }
    if switched != 0 {
      let rotated = result.rotate_negacyclic(-switched)
      result = match self.controls[index].cmux(rotated, result) {
        Ok(value) => value
        Err(_) => return Err(BlindRotationFailure)
      }
    }
  }
  Ok(result)
}

///|
pub fn BootstrapKey::programmable_bootstrap(
  self : BootstrapKey,
  input : @lwe.LweCiphertext,
  lut : BooleanLut,
) -> Result[@lwe.LweCiphertext, PbsError] {
  if self.order is KeyswitchBootstrap {
    return Err(UnsupportedOrder)
  }
  let accumulator = match lut.accumulator(self.glwe_parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let rotated = match self.blind_rotate(accumulator, input) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let extracted = match rotated.sample_extract(0) {
    Ok(value) => value
    Err(_) => return Err(SampleExtractionFailure)
  }
  match self.key_switch.apply(extracted) {
    Ok(value) => Ok(value)
    Err(_) => Err(KeyswitchFailure)
  }
}

///|
test "pbs: Boolean LUT reference preserves both torus outputs" {
  let lut = boolean_lut(
    @torus.Torus32::from_int(-0x2000_0000),
    @torus.Torus32::from_int(0x2000_0000),
  )
  assert_eq(lut.evaluate_reference(false).to_int(), -0x2000_0000)
  assert_eq(lut.evaluate_reference(true).to_int(), 0x2000_0000)
}

///|
test "pbs: typed blind rotation evaluates ID and NOT without a secret key" {
  let input_dimension = @params.lwe_dimension(2).unwrap()
  let input_bits = [true, false]
  let input_key = @lwe.lwe_key_from_binary_secret(input_dimension, input_bits).unwrap()
  let glwe_parameters = @glwe.glwe_parameters(1, 8).unwrap()
  let glwe_key = @glwe.glwe_keygen(
    glwe_parameters,
    @random.test_rng_new(0x504253474C5745),
  )
  let extracted_key = glwe_key.to_extracted_lwe_key().unwrap()
  let decomposition = @params.decomposition_parameters(4, 8).unwrap()
  let noise = @random.gaussian_sigma_3_fixture()
  let key_switch = @keyswitch.keyswitch_keygen(
    extracted_key,
    input_key,
    decomposition,
    noise,
    @random.test_rng_new(0x5042534B534B),
  ).unwrap()
  let ggsw_parameters = @ggsw.ggsw_parameters(glwe_parameters, 4, 8).unwrap()
  let controls : Array[@ggsw.GgswCiphertext] = []
  for index in 0..<input_bits.length() {
    controls.push(
      @ggsw.ggsw_encrypt_boolean(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        noise,
        @random.test_rng_new(0x50425342534B + index.to_uint64()),
      ).unwrap(),
    )
  }
  let bootstrap_key = bootstrap_key_from_encrypted_parts(
    input_dimension,
    glwe_parameters,
    controls,
    key_switch,
    BootstrapKeyswitch,
  ).unwrap()
  let amplitude = @torus.Torus32::from_int(0x2000_0000)
  for message in [false, true] {
    let ciphertext = input_key
      .lwe_encrypt_binary(
        message,
        noise,
        @random.test_rng_new(
          if message {
            0x50425354525545
          } else {
            0x50425346414C53
          },
        ),
      )
      .unwrap()
    let identity = bootstrap_key
      .programmable_bootstrap(
        ciphertext,
        boolean_lut(amplitude.neg(), amplitude),
      )
      .unwrap()
    let negated = bootstrap_key
      .programmable_bootstrap(
        ciphertext,
        boolean_lut(amplitude, amplitude.neg()),
      )
      .unwrap()
    assert_eq(input_key.lwe_decrypt_binary(identity), Ok(message))
    assert_eq(input_key.lwe_decrypt_binary(negated), Ok(!message))
  }
}
