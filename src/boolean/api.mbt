///|
/// Parameter metadata owned by the stable Boolean facade.
pub struct BooleanParameters {
  id : String
  security : @params.SecurityMetadata
  test_only : Bool
  dimension : Int
  record : @params.ParameterSet
}

///|
pub suberror KeyGenerationError {
  UnsupportedBackend
  InvalidParameters
} derive(Debug, Eq)

///|
pub suberror DecryptionError {
  KeyMismatch
  InvalidCiphertext
} derive(Debug, Eq)

///|
#warnings("-unused_constructor")
pub suberror EvaluationError {
  KeyMismatch
  InvalidCiphertext
  UnsupportedLut
  InvalidLutLength
} derive(Debug, Eq)

///|
pub suberror LutError {
  InvalidLength
  InvalidPolynomialSize
  InvalidAntiPeriodicity
} derive(Debug, Eq)

///|
pub suberror SerializationError {
  InvalidMagic
  UnsupportedVersion
  InvalidLength
  ParameterMismatch
  ChecksumMismatch
  InvalidCiphertext
  InvalidServerKey
  InvalidKeyLength
  AuthenticationFailed
  UnsupportedBackend
} derive(Debug, Eq)

///|
priv enum BinaryLut {
  NandLut
  AndLut
  OrLut
  XorLut
  XnorLut
}

///|
/// Opaque Boolean ciphertext.
pub struct Ciphertext {
  priv inner : @lwe.LweCiphertext
  priv key_id : @params.KeyId
  priv parameters : BooleanParameters
}

///|
/// Client-side secret key. The secret representation is owned by the core
/// package and is not exposed through this facade.
pub struct ClientKey {
  priv inner : @lwe.LweSecretKey
  priv mask_rng : @random.RandomGenerator
  priv noise_rng : @random.RandomGenerator
  priv serialization_rng : @random.RandomGenerator
  priv encryption_noise : @random.DiscreteGaussian
  priv parameters : BooleanParameters
  priv key_id : @params.KeyId
}

///|
/// Secret-free evaluation key.
pub struct ServerKey {
  priv inner : @pbs.BootstrapKey
  priv parameters : BooleanParameters
  priv key_id : @params.KeyId
}

///|
/// Opaque per-evaluation state. The current native provider owns the heavy
/// PBS workspace behind `ServerKey`; this context is the stable place for
/// explicit workspace reuse and future concurrent evaluators.
pub struct EvaluationContext {
  priv server_key : ServerKey
}

///|
/// A validated anti-periodic Torus lookup table for programmable bootstrap.
pub struct ProgrammableBootstrapLut {
  priv values : Array[@torus.Torus32]
  priv polynomial_size : Int
}

///|
pub fn ServerKey::evaluation_context(self : ServerKey) -> EvaluationContext {
  { server_key: self }
}

///|
pub fn programmable_bootstrap_lut(
  parameters : BooleanParameters,
  values : Array[@torus.Torus32],
) -> Result[ProgrammableBootstrapLut, LutError] {
  let polynomial_size = parameters.record.polynomial_size().value()
  if polynomial_size <= 0 || (polynomial_size & (polynomial_size - 1)) != 0 {
    return Err(InvalidPolynomialSize)
  }
  if values.length() != polynomial_size {
    return Err(InvalidLength)
  }
  let half = polynomial_size / 2
  for index in 0..<half {
    if values[index + half] != values[index].neg() {
      return Err(InvalidAntiPeriodicity)
    }
  }
  Ok({ values: values.copy(), polynomial_size })
}

///|
pub fn ProgrammableBootstrapLut::polynomial_size(
  self : ProgrammableBootstrapLut,
) -> Int {
  self.polynomial_size
}

///|
/// Best-effort destruction of secret material retained by the client key.
/// Native provider buffers are finalized separately; GC runtimes can only
/// overwrite currently reachable storage.
pub fn ClientKey::destroy(self : ClientKey) -> Unit {
  self.inner.destroy()
  self.mask_rng.destroy()
  self.noise_rng.destroy()
  self.serialization_rng.destroy()
}

///|
pub fn boolean_110_parameters() -> BooleanParameters {
  let record = @params.boolean_110_reference()
  {
    id: "tfhe-rs-boolean-110-reference".to_string(),
    security: record.security_metadata(),
    test_only: false,
    dimension: 805,
    record,
  }
}

///|
pub fn boolean_128_parameters() -> BooleanParameters {
  let record = @params.boolean_128_reference()
  {
    id: "tfhe-rs-boolean-128-reference".to_string(),
    security: record.security_metadata(),
    test_only: false,
    dimension: 837,
    record,
  }
}

///|
/// Tiny deterministic parameters used only by contract tests and examples.
pub fn boolean_test_parameters() -> BooleanParameters {
  let record = @params.boolean_test_record()
  {
    id: "moontfhe-boolean-test".to_string(),
    security: record.security_metadata(),
    test_only: true,
    dimension: 4,
    record,
  }
}

///|
pub fn BooleanParameters::id(self : BooleanParameters) -> String {
  self.id
}

///|
pub fn BooleanParameters::security_bits(self : BooleanParameters) -> Int {
  self.security.target_security_bits()
}

///|
pub fn BooleanParameters::is_test_only(self : BooleanParameters) -> Bool {
  self.test_only
}

///|
/// Production construction is native-first. Portable implementations reject
/// unsupported standard backends before allocating evaluation material.
pub fn generate_keys(
  parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  if parameters.test_only || parameters.dimension <= 0 {
    return Err(InvalidParameters)
  }
  if parameters.record.validate() is Err(_) {
    return Err(InvalidParameters)
  }
  generate_standard_keys_impl(parameters)
}

///|
/// Deterministic key generation for tests only. This function is not part of
/// the production security boundary.
pub fn generate_test_keys(
  parameters : BooleanParameters,
  seed : UInt64,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  if !parameters.test_only || parameters.dimension != 4 {
    return Err(InvalidParameters)
  }
  if parameters.record.validate() is Err(_) {
    return Err(InvalidParameters)
  }
  let input_dimension = match @params.lwe_dimension(parameters.dimension) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let glwe = match
    @glwe.glwe_parameters(
      parameters.record.glwe_dimension().value(),
      parameters.record.polynomial_size().value(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let key_rng = @random.test_rng_new(seed)
  let input_bits = Array::makei(parameters.dimension, fn(_) {
    (key_rng.next_u32() & 1U) == 1U
  })
  let input_key = @lwe.lwe_key_from_binary_secret_unchecked(
    input_dimension, input_bits,
  )
  let glwe_data = Array::makei(glwe.glwe_dimension(), fn(_) {
    Array::makei(glwe.polynomial_size(), fn(_) {
      (key_rng.next_u32() & 1U) == 1U
    })
  })
  let glwe_key = match @glwe.glwe_key_from_binary_secret(glwe, glwe_data) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let extracted_key = match glwe_key.to_extracted_lwe_key() {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let noise = @random.test_zero_noise_fixture()
  let key_switch = match
    @keyswitch.keyswitch_keygen(
      extracted_key,
      input_key,
      parameters.record.ks_decomposition(),
      noise,
      @random.test_rng_new(seed ^ 0x4B534BUL),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let ggsw_parameters = match
    @ggsw.ggsw_parameters(
      glwe,
      parameters.record.pbs_decomposition().base_log(),
      parameters.record.pbs_decomposition().level(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let controls : Array[@ggsw.GgswCiphertext] = []
  for index in 0..<input_bits.length() {
    let control = match
      @ggsw.ggsw_encrypt_boolean(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        noise,
        @random.test_rng_new(seed ^ (0x42534B00UL + index.to_uint64())),
      ) {
      Ok(value) => value
      Err(_) => return Err(InvalidParameters)
    }
    controls.push(control)
  }
  let bootstrap = match
    @pbs.bootstrap_key_from_encrypted_parts(
      input_dimension,
      glwe,
      controls,
      key_switch,
      @pbs.bootstrap_keyswitch_order(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let key_id = @params.key_id_from_words(0x4D54464854455354UL, seed)
  let client_key : ClientKey = {
    inner: input_key,
    mask_rng: @random.test_rng_new(seed ^ 0x454D41534BUL),
    noise_rng: @random.test_rng_new(seed ^ 0x454E4F4953UL),
    serialization_rng: @random.test_rng_new(seed ^ 0x534E4F4E43UL),
    encryption_noise: noise,
    parameters,
    key_id,
  }
  let server_key : ServerKey = { inner: bootstrap, parameters, key_id }
  Ok((client_key, server_key))
}

///|
/// Correct portable standard construction. It intentionally uses the
/// coefficient reference backend and is only exercised by scheduled smoke.
#warnings("-unused_value")
fn generate_standard_reference_keys(
  parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  let security_bits = parameters.security.target_security_bits()
  if security_bits != 110 && security_bits != 128 {
    return Err(InvalidParameters)
  }
  let key_rng = match
    @random.secure_rng_new_for(@random.key_generation_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let mask_rng = match @random.secure_encryption_mask_rng_new() {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let noise_rng = match @random.secure_encryption_noise_rng_new() {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let bsk_rng = match
    @random.secure_rng_new_for(@random.bootstrap_key_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let serialization_rng = match
    @random.secure_rng_new_for(@random.serialization_nonce_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let input_dimension = parameters.record.lwe_dimension()
  let input_bits = Array::makei(input_dimension.value(), fn(_) {
    (key_rng.next_u32() & 1U) == 1U
  })
  let input_key = @lwe.lwe_key_from_binary_secret_unchecked(
    input_dimension, input_bits,
  )
  let glwe = match
    @glwe.glwe_parameters(
      parameters.record.glwe_dimension().value(),
      parameters.record.polynomial_size().value(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let glwe_key = @glwe.glwe_keygen(glwe, key_rng)
  let extracted_key = match glwe_key.to_extracted_lwe_key() {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let lwe_noise = if security_bits == 110 {
    @random.gaussian_boolean_110_lwe_fixture()
  } else {
    @random.gaussian_boolean_128_lwe_fixture()
  }
  let glwe_noise = if security_bits == 110 {
    @random.gaussian_boolean_110_glwe_fixture()
  } else {
    @random.gaussian_boolean_128_glwe_fixture()
  }
  let key_switch = match
    @keyswitch.keyswitch_keygen(
      extracted_key,
      input_key,
      parameters.record.ks_decomposition(),
      lwe_noise,
      bsk_rng,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let ggsw_parameters = match
    @ggsw.ggsw_parameters(
      glwe,
      parameters.record.pbs_decomposition().base_log(),
      parameters.record.pbs_decomposition().level(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let control_size = ggsw_parameters.flat_size()
  let coefficient_bsk = FixedArray::make(
    input_dimension.value() * control_size,
    0U,
  )
  for index in 0..<input_dimension.value() {
    let control = match
      @ggsw.ggsw_encrypt_boolean(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        glwe_noise,
        bsk_rng,
      ) {
      Ok(value) => value
      Err(_) => return Err(InvalidParameters)
    }
    let flat = control.flat_u32_copy()
    for offset in 0..<control_size {
      coefficient_bsk[index * control_size + offset] = flat[offset]
    }
  }
  let bootstrap = match
    @pbs.bootstrap_key_from_flat_encrypted_parts(
      input_dimension,
      glwe,
      ggsw_parameters,
      coefficient_bsk,
      key_switch,
      @pbs.bootstrap_keyswitch_order(),
      None,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidParameters)
  }
  let key_id = @params.key_id_from_words(key_rng.next_u64(), key_rng.next_u64())
  Ok(
    (
      {
        inner: input_key,
        mask_rng,
        noise_rng,
        serialization_rng,
        encryption_noise: lwe_noise,
        parameters,
        key_id,
      },
      { inner: bootstrap, parameters, key_id },
    ),
  )
}

///|
pub fn ClientKey::encrypt(self : ClientKey, message : Bool) -> Ciphertext {
  let inner = self.inner.lwe_encrypt_torus_with_streams(
    if message {
      @torus.Torus32::from_int(0x2000_0000)
    } else {
      @torus.Torus32::from_int(-0x2000_0000)
    },
    self.encryption_noise,
    self.mask_rng,
    self.noise_rng,
  )
  { inner, key_id: self.key_id, parameters: self.parameters }
}

///|
pub fn ClientKey::decrypt(
  self : ClientKey,
  ciphertext : Ciphertext,
) -> Result[Bool, DecryptionError] {
  if ciphertext.key_id != self.key_id {
    return Err(KeyMismatch)
  }
  match self.inner.lwe_decrypt_binary(ciphertext.inner) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
fn evaluate_check(
  parameters : BooleanParameters,
  key_id : @params.KeyId,
  ciphertext : Ciphertext,
) -> Result[Unit, EvaluationError] {
  if ciphertext.key_id != key_id {
    return Err(KeyMismatch)
  }
  if parameters.dimension <= 0 {
    return Err(InvalidCiphertext)
  }
  Ok(())
}

///|
fn boolean_amplitude() -> @torus.Torus32 {
  @torus.Torus32::from_int(0x2000_0000)
}

///|
fn boolean_packed_layout_id() -> Byte {
  b'\x02'
}

///|
fn boolean_nand_table(
  polynomial_size : Int,
  magnitude : @torus.Torus32,
) -> Array[@torus.Torus32] {
  Array::makei(polynomial_size, fn(rotation) {
    let first = polynomial_size / 8
    let third = 3 * polynomial_size / 8
    let fifth = 5 * polynomial_size / 8
    let seventh = 7 * polynomial_size / 8
    if (rotation >= first && rotation < third) ||
      (rotation >= fifth && rotation < seventh) {
      magnitude
    } else {
      magnitude.neg()
    }
  })
}

///|
fn ServerKey::binary_nand_encoded(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
  magnitude : @torus.Torus32,
) -> Result[Ciphertext, EvaluationError] {
  match evaluate_check(self.parameters, self.key_id, left) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match evaluate_check(self.parameters, self.key_id, right) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let combined = match left.inner.add(right.inner) {
    Ok(value) => value.sub_plain(boolean_amplitude())
    Err(_) => return Err(InvalidCiphertext)
  }
  let table = boolean_nand_table(
    self.parameters.record.polynomial_size().value(),
    magnitude,
  )
  match self.inner.programmable_bootstrap_table(combined, table) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
fn ServerKey::binary_and_encoded(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
  magnitude : @torus.Torus32,
) -> Result[Ciphertext, EvaluationError] {
  match self.binary_nand_encoded(left, right, magnitude) {
    Ok(value) =>
      Ok({
        inner: value.inner.neg(),
        key_id: value.key_id,
        parameters: value.parameters,
      })
    Err(error) => Err(error)
  }
}

///|
fn ServerKey::binary_xor(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  match evaluate_check(self.parameters, self.key_id, left) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match evaluate_check(self.parameters, self.key_id, right) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  let combined = match left.inner.add(right.inner) {
    Ok(value) => value.scale(2).add_plain(boolean_amplitude())
    Err(_) => return Err(InvalidCiphertext)
  }
  let identity = @pbs.boolean_lut(
    boolean_amplitude().neg(),
    boolean_amplitude(),
  )
  match self.inner.programmable_bootstrap(combined, identity) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
pub fn ServerKey::not(
  self : ServerKey,
  ciphertext : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  match evaluate_check(self.parameters, self.key_id, ciphertext) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  Ok({
    inner: ciphertext.inner.neg(),
    key_id: self.key_id,
    parameters: self.parameters,
  })
}

///|
pub fn EvaluationContext::not(
  self : EvaluationContext,
  ciphertext : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.not(ciphertext)
}

///|
fn ServerKey::apply_binary_lut(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
  table : BinaryLut,
) -> Result[Ciphertext, EvaluationError] {
  match table {
    NandLut => self.binary_nand_encoded(left, right, boolean_amplitude())
    AndLut => self.binary_and_encoded(left, right, boolean_amplitude())
    OrLut => {
      let not_left = match self.not(left) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let not_right = match self.not(right) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      self.binary_nand_encoded(not_left, not_right, boolean_amplitude())
    }
    XorLut => self.binary_xor(left, right)
    XnorLut =>
      match self.binary_xor(left, right) {
        Ok(value) => self.not(value)
        Err(error) => Err(error)
      }
  }
}

///|
pub fn ServerKey::nand(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.apply_binary_lut(left, right, NandLut)
}

///|
pub fn EvaluationContext::nand(
  self : EvaluationContext,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.nand(left, right)
}

///|
pub fn ServerKey::and_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.apply_binary_lut(left, right, AndLut)
}

///|
pub fn EvaluationContext::and_gate(
  self : EvaluationContext,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.and_gate(left, right)
}

///|
pub fn ServerKey::or_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.apply_binary_lut(left, right, OrLut)
}

///|
pub fn EvaluationContext::or_gate(
  self : EvaluationContext,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.or_gate(left, right)
}

///|
/// Evaluate XOR with one PBS. Doubling the summed phase makes `00` and `11`
/// coincide half a Torus turn away from the mixed inputs; the public bias keeps
/// both classes away from the accumulator discontinuity.
pub fn ServerKey::xor_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.apply_binary_lut(left, right, XorLut)
}

///|
pub fn EvaluationContext::xor_gate(
  self : EvaluationContext,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.xor_gate(left, right)
}

///|
pub fn ServerKey::xnor_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.apply_binary_lut(left, right, XnorLut)
}

///|
pub fn EvaluationContext::xnor_gate(
  self : EvaluationContext,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.xnor_gate(left, right)
}

///|
/// Select `when_true` when `selector` is true, otherwise `when_false`.
pub fn ServerKey::mux(
  self : ServerKey,
  selector : Ciphertext,
  when_true : Ciphertext,
  when_false : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  // The two PBS results use +/-mu/2. Exactly one branch can be selected, so
  // `2 * (selected_true + selected_false) + mu` restores the public +/-mu
  // Boolean encoding without a third PBS.
  let half_amplitude = @torus.Torus32::from_int(0x1000_0000)
  let selected_true = match
    self.binary_and_encoded(selector, when_true, half_amplitude) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let not_selector = match self.not(selector) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let selected_false = match
    self.binary_and_encoded(not_selector, when_false, half_amplitude) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match selected_true.inner.add(selected_false.inner) {
    Ok(value) =>
      Ok({
        inner: value.scale(2).add_plain(boolean_amplitude()),
        key_id: self.key_id,
        parameters: self.parameters,
      })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
pub fn EvaluationContext::mux(
  self : EvaluationContext,
  selector : Ciphertext,
  when_true : Ciphertext,
  when_false : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.mux(selector, when_true, when_false)
}

///|
/// Evaluate the complete two-point Boolean LUT family. Constant tables are
/// derived homomorphically and do not require server-side secret material.
pub fn ServerKey::apply_lut(
  self : ServerKey,
  ciphertext : Ciphertext,
  table : Array[Bool],
) -> Result[Ciphertext, EvaluationError] {
  if table.length() != 2 {
    return Err(InvalidLutLength)
  }
  match evaluate_check(self.parameters, self.key_id, ciphertext) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match (table[0], table[1]) {
    (false, true) => Ok(ciphertext)
    (true, false) => self.not(ciphertext)
    (false, false) => {
      let zero = match ciphertext.inner.add(ciphertext.inner.neg()) {
        Ok(value) => value
        Err(_) => return Err(InvalidCiphertext)
      }
      Ok({
        inner: zero.add_plain(boolean_amplitude().neg()),
        key_id: self.key_id,
        parameters: self.parameters,
      })
    }
    (true, true) => {
      let zero = match ciphertext.inner.add(ciphertext.inner.neg()) {
        Ok(value) => value
        Err(_) => return Err(InvalidCiphertext)
      }
      Ok({
        inner: zero.add_plain(boolean_amplitude()),
        key_id: self.key_id,
        parameters: self.parameters,
      })
    }
  }
}

///|
pub fn ServerKey::apply_programmable_lut(
  self : ServerKey,
  ciphertext : Ciphertext,
  lut : ProgrammableBootstrapLut,
) -> Result[Ciphertext, EvaluationError] {
  match evaluate_check(self.parameters, self.key_id, ciphertext) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  if lut.polynomial_size != self.parameters.record.polynomial_size().value() {
    return Err(InvalidLutLength)
  }
  match self.inner.programmable_bootstrap_table(ciphertext.inner, lut.values) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
pub fn EvaluationContext::apply_programmable_lut(
  self : EvaluationContext,
  ciphertext : Ciphertext,
  lut : ProgrammableBootstrapLut,
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.apply_programmable_lut(ciphertext, lut)
}

///|
pub fn EvaluationContext::apply_lut(
  self : EvaluationContext,
  ciphertext : Ciphertext,
  table : Array[Bool],
) -> Result[Ciphertext, EvaluationError] {
  self.server_key.apply_lut(ciphertext, table)
}

///|
pub fn Ciphertext::serialize(self : Ciphertext) -> Bytes {
  let dimension = self.inner.parameters().value()
  let payload = Array::make(4 * (dimension + 1), b'\x00')
  let mask = self.inner.a()
  for index in 0..<dimension {
    boolean_write_u32(payload, index * 4, mask[index].to_uint())
  }
  boolean_write_u32(payload, dimension * 4, self.inner.b().to_uint())
  let payload = Bytes::from_array(payload)
  let header_length = 70
  let output = Array::make(header_length + payload.length(), b'\x00')
  output[0] = b'M'
  output[1] = b'B'
  output[2] = b'C'
  output[3] = b'T'
  output[4] = b'\x03'
  output[5] = boolean_packed_layout_id()
  boolean_write_parameter_fields(output, self.parameters)
  boolean_write_key_id(output, 46, self.key_id)
  boolean_write_u32(output, 62, payload.length().reinterpret_as_uint())
  for i in 0..<payload.length() {
    output[header_length + i] = payload[i]
  }
  boolean_write_u32(
    output,
    66,
    boolean_crc32c_envelope_array(output, 66, header_length, payload.length()),
  )
  Bytes::from_array(output)
}

///|
pub fn ClientKey::deserialize(
  self : ClientKey,
  bytes : Bytes,
) -> Result[Ciphertext, SerializationError] {
  if bytes.length() < 5 {
    return Err(InvalidLength)
  }
  if bytes[0] != b'M' ||
    bytes[1] != b'B' ||
    bytes[2] != b'C' ||
    bytes[3] != b'T' {
    return Err(InvalidMagic)
  }
  let version = bytes[4]
  let header_length = 70
  let mut parameter_code = 0
  let mut dimension = 0
  let mut key_id = @params.key_id_from_words(0UL, 0UL)
  let mut payload_length = 0
  let mut payload = Bytes::make(0, 0)
  let mut checksum_ok = false
  if version != b'\x03' || bytes.length() < header_length {
    return Err(UnsupportedVersion)
  }
  if bytes[5] != boolean_packed_layout_id() {
    return Err(InvalidCiphertext)
  }
  parameter_code = boolean_read_u32(bytes, 6).reinterpret_as_int()
  dimension = boolean_read_u32(bytes, 10).reinterpret_as_int()
  key_id = boolean_read_key_id(bytes, 46)
  if !boolean_validate_parameter_fields(bytes, self.parameters) {
    return Err(ParameterMismatch)
  }
  payload_length = boolean_read_u32(bytes, 62).reinterpret_as_int()
  let expected_payload_length = 4 * (self.parameters.dimension + 1)
  if payload_length != expected_payload_length ||
    bytes.length() != header_length + expected_payload_length {
    return Err(InvalidLength)
  }
  payload = bytes[header_length:].to_owned()
  checksum_ok = boolean_crc32c_envelope(
      bytes, 66, header_length, payload_length,
    ) ==
    boolean_read_u32(bytes, 66)
  if parameter_code != boolean_parameter_code(self.parameters) ||
    dimension != self.parameters.dimension ||
    key_id != self.key_id {
    return Err(ParameterMismatch)
  }
  if !checksum_ok {
    return Err(ChecksumMismatch)
  }
  match boolean_decode_lwe_payload(self.inner.parameters(), payload) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
fn boolean_decode_lwe_payload(
  parameters : @params.LweDimension,
  payload : Bytes,
) -> Result[@lwe.LweCiphertext, SerializationError] {
  let expected = 4 * (parameters.value() + 1)
  if payload.length() != expected {
    return Err(InvalidCiphertext)
  }
  let a = Array::makei(parameters.value(), fn(index) {
    @torus.Torus32::from_uint(boolean_read_u32(payload, index * 4))
  })
  match
    @lwe.lwe_ciphertext_from_parts(
      parameters,
      a,
      @torus.Torus32::from_uint(
        boolean_read_u32(payload, parameters.value() * 4),
      ),
    ) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
fn boolean_parameter_code(parameters : BooleanParameters) -> Int {
  if parameters.test_only {
    0
  } else if parameters.security.target_security_bits() == 110 {
    110
  } else {
    128
  }
}

///|
fn boolean_parameters_from_code(
  code : Int,
) -> Result[BooleanParameters, SerializationError] {
  if code == 0 {
    Ok(boolean_test_parameters())
  } else if code == 110 {
    Ok(boolean_110_parameters())
  } else if code == 128 {
    Ok(boolean_128_parameters())
  } else {
    Err(ParameterMismatch)
  }
}

///|
fn boolean_distribution_code(parameters : BooleanParameters) -> UInt {
  if parameters.test_only {
    0U
  } else {
    1U
  }
}

///|
fn boolean_write_parameter_fields(
  output : Array[Byte],
  parameters : BooleanParameters,
) -> Unit {
  boolean_write_u32(
    output,
    6,
    boolean_parameter_code(parameters).reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    10,
    parameters.record.lwe_dimension().value().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    14,
    parameters.record.glwe_dimension().value().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    18,
    parameters.record.polynomial_size().value().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    22,
    parameters.record.pbs_decomposition().base_log().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    26,
    parameters.record.pbs_decomposition().level().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    30,
    parameters.record.ks_decomposition().base_log().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    34,
    parameters.record.ks_decomposition().level().reinterpret_as_uint(),
  )
  // Torus32 uses modulus 2^32, encoded as zero modulo 2^32.
  boolean_write_u32(output, 38, 0U)
  boolean_write_u32(output, 42, boolean_distribution_code(parameters))
}

///|
fn boolean_validate_parameter_fields(
  input : Bytes,
  parameters : BooleanParameters,
) -> Bool {
  boolean_read_u32(input, 6).reinterpret_as_int() ==
  boolean_parameter_code(parameters) &&
  boolean_read_u32(input, 10).reinterpret_as_int() ==
  parameters.record.lwe_dimension().value() &&
  boolean_read_u32(input, 14).reinterpret_as_int() ==
  parameters.record.glwe_dimension().value() &&
  boolean_read_u32(input, 18).reinterpret_as_int() ==
  parameters.record.polynomial_size().value() &&
  boolean_read_u32(input, 22).reinterpret_as_int() ==
  parameters.record.pbs_decomposition().base_log() &&
  boolean_read_u32(input, 26).reinterpret_as_int() ==
  parameters.record.pbs_decomposition().level() &&
  boolean_read_u32(input, 30).reinterpret_as_int() ==
  parameters.record.ks_decomposition().base_log() &&
  boolean_read_u32(input, 34).reinterpret_as_int() ==
  parameters.record.ks_decomposition().level() &&
  boolean_read_u32(input, 38) == 0U &&
  boolean_read_u32(input, 42) == boolean_distribution_code(parameters)
}

///|
fn boolean_checked_add(left : Int, right : Int, limit : Int) -> Int? {
  if left < 0 || right < 0 || left > limit - right {
    None
  } else {
    Some(left + right)
  }
}

///|
fn boolean_checked_mul(left : Int, right : Int, limit : Int) -> Int? {
  if left < 0 || right < 0 || (right != 0 && left > limit / right) {
    None
  } else {
    Some(left * right)
  }
}

///|
fn boolean_write_u32(output : Array[Byte], offset : Int, value : UInt) -> Unit {
  output[offset] = value.to_byte()
  output[offset + 1] = (value >> 8).to_byte()
  output[offset + 2] = (value >> 16).to_byte()
  output[offset + 3] = (value >> 24).to_byte()
}

///|
fn boolean_write_u64(
  output : Array[Byte],
  offset : Int,
  value : UInt64,
) -> Unit {
  boolean_write_u32(output, offset, value.to_uint())
  boolean_write_u32(output, offset + 4, (value >> 32).to_uint())
}

///|
fn boolean_write_key_id(
  output : Array[Byte],
  offset : Int,
  key_id : @params.KeyId,
) -> Unit {
  boolean_write_u64(output, offset, key_id.high())
  boolean_write_u64(output, offset + 8, key_id.low())
}

///|
fn boolean_read_u32(input : Bytes, offset : Int) -> UInt {
  input[offset].to_uint() |
  (input[offset + 1].to_uint() << 8) |
  (input[offset + 2].to_uint() << 16) |
  (input[offset + 3].to_uint() << 24)
}

///|
fn boolean_read_u64(input : Bytes, offset : Int) -> UInt64 {
  boolean_read_u32(input, offset).to_uint64() |
  (boolean_read_u32(input, offset + 4).to_uint64() << 32)
}

///|
fn boolean_read_key_id(input : Bytes, offset : Int) -> @params.KeyId {
  @params.key_id_from_words(
    boolean_read_u64(input, offset),
    boolean_read_u64(input, offset + 8),
  )
}

///|
/// Castagnoli CRC32C over immutable envelope metadata and payload.
fn boolean_crc32c_envelope(
  bytes : Bytes,
  checksum_offset : Int,
  payload_offset : Int,
  payload_length : Int,
) -> UInt {
  let mut crc = 0xFFFFFFFFU
  for index in 0..<checksum_offset {
    crc = crc ^ bytes[index].to_uint()
    for _ in 0..<8 {
      let mask = 0U - (crc & 1U)
      crc = (crc >> 1) ^ (0x82F63B78U & mask)
    }
  }
  for index in payload_offset..<(payload_offset + payload_length) {
    crc = crc ^ bytes[index].to_uint()
    for _ in 0..<8 {
      let mask = 0U - (crc & 1U)
      crc = (crc >> 1) ^ (0x82F63B78U & mask)
    }
  }
  crc ^ 0xFFFFFFFFU
}

///|
fn boolean_crc32c_envelope_array(
  bytes : Array[Byte],
  checksum_offset : Int,
  payload_offset : Int,
  payload_length : Int,
) -> UInt {
  let mut crc = 0xFFFFFFFFU
  for index in 0..<checksum_offset {
    crc = crc ^ bytes[index].to_uint()
    for _ in 0..<8 {
      let mask = 0U - (crc & 1U)
      crc = (crc >> 1) ^ (0x82F63B78U & mask)
    }
  }
  for index in payload_offset..<(payload_offset + payload_length) {
    crc = crc ^ bytes[index].to_uint()
    for _ in 0..<8 {
      let mask = 0U - (crc & 1U)
      crc = (crc >> 1) ^ (0x82F63B78U & mask)
    }
  }
  crc ^ 0xFFFFFFFFU
}

///|
/// Explicit AES-GCM export boundary. A missing host provider is an error,
/// never a deterministic or plaintext fallback.
pub fn ClientKey::export_secret(
  self : ClientKey,
  key : SerializationKey,
) -> Result[Bytes, SerializationError] {
  if key.bytes.length() != 32 {
    return Err(InvalidKeyLength)
  }
  let payload_length = 9 + (self.parameters.dimension + 7) / 8
  let header_length = 66
  let header = Array::make(header_length, b'\x00')
  header[0] = b'M'
  header[1] = b'T'
  header[2] = b'S'
  header[3] = b'K'
  header[4] = b'\x02'
  header[5] = boolean_packed_layout_id()
  boolean_write_parameter_fields(header, self.parameters)
  boolean_write_key_id(header, 46, self.key_id)
  boolean_write_u32(header, 62, payload_length.reinterpret_as_uint())
  let nonce = Array::make(12, b'\x00')
  for word_index in 0..<3 {
    let word = self.serialization_rng.next_u32()
    for byte_index in 0..<4 {
      nonce[word_index * 4 + byte_index] = (word >> (byte_index * 8)).to_byte()
    }
  }
  let payload_array = self.inner.secret_export_payload_array()
  let payload = Bytes::from_array(payload_array)
  let encrypted_result = boolean_aead_encrypt(
    key.bytes,
    Bytes::from_array(nonce),
    Bytes::from_array(header),
    payload,
  )
  // Clear the mutable source immediately after the provider call. The Bytes
  // view is still subject to GC lifetime rules, so this is best effort.
  payload_array.fill(b'\x00')
  let encrypted = match encrypted_result {
    Ok(value) => value
    Err(UnsupportedBackend(_)) => return Err(UnsupportedBackend)
    Err(EntropyUnavailable) => return Err(UnsupportedBackend)
    Err(InvalidProviderOutput) => return Err(InvalidLength)
  }
  if encrypted.length() != payload_length + 16 {
    return Err(InvalidLength)
  }
  let output = Array::make(header_length + 12 + encrypted.length(), b'\x00')
  for index in 0..<header_length {
    output[index] = header[index]
  }
  for index in 0..<12 {
    output[header_length + index] = nonce[index]
  }
  for index in 0..<encrypted.length() {
    output[header_length + 12 + index] = encrypted[index]
  }
  Ok(Bytes::from_array(output))
}

///|
/// Import an explicitly encrypted `MTSK v2` client key. The caller supplies
/// both the expected parameter set and the 256-bit serialization key; neither
/// is inferred from passwords, timestamps, or KeyId metadata.
pub fn ClientKey::import_secret(
  parameters : BooleanParameters,
  key : SerializationKey,
  bytes : Bytes,
) -> Result[ClientKey, SerializationError] {
  let header_length = 66
  let nonce_length = 12
  let tag_length = 16
  if key.bytes.length() != 32 {
    return Err(InvalidKeyLength)
  }
  if bytes.length() < header_length + nonce_length + tag_length {
    return Err(InvalidLength)
  }
  if bytes[0] != b'M' ||
    bytes[1] != b'T' ||
    bytes[2] != b'S' ||
    bytes[3] != b'K' {
    return Err(InvalidMagic)
  }
  if bytes[4] != b'\x02' {
    return Err(UnsupportedVersion)
  }
  if bytes[5] != boolean_packed_layout_id() {
    return Err(InvalidCiphertext)
  }
  let dimension = boolean_read_u32(bytes, 10).reinterpret_as_int()
  let key_id = boolean_read_key_id(bytes, 46)
  let payload_length = boolean_read_u32(bytes, 62).reinterpret_as_int()
  if !boolean_validate_parameter_fields(bytes, parameters) ||
    dimension != parameters.dimension {
    return Err(ParameterMismatch)
  }
  let expected_payload_length = 9 + (parameters.dimension + 7) / 8
  if payload_length != expected_payload_length ||
    bytes.length() != header_length + nonce_length + payload_length + tag_length {
    return Err(InvalidLength)
  }
  let aad = bytes[:header_length].to_owned()
  let nonce = bytes[header_length:header_length + nonce_length].to_owned()
  let encrypted = bytes[header_length + nonce_length:].to_owned()
  let payload = match boolean_aead_decrypt(key.bytes, nonce, aad, encrypted) {
    Ok(value) => value
    Err(UnsupportedBackend(_)) => return Err(UnsupportedBackend)
    Err(EntropyUnavailable) => return Err(UnsupportedBackend)
    Err(InvalidProviderOutput) => return Err(AuthenticationFailed)
  }
  if payload.length() != payload_length ||
    payload[0] != b'M' ||
    payload[1] != b'S' ||
    payload[2] != b'C' ||
    payload[3] != b'R' ||
    payload[4] != b'\x01' {
    return Err(InvalidCiphertext)
  }
  let secret_dimension = boolean_read_u32(payload, 5).reinterpret_as_int()
  if secret_dimension != dimension ||
    payload.length() != 9 + (secret_dimension + 7) / 8 {
    return Err(ParameterMismatch)
  }
  let bits = Array::makei(secret_dimension, fn(index) {
    let value = payload[9 + index / 8].to_uint()
    ((value >> (index % 8)) & 1U) == 1U
  })
  let lwe_dimension = match @params.lwe_dimension(secret_dimension) {
    Ok(value) => value
    Err(_) => return Err(InvalidCiphertext)
  }
  let secret = match @lwe.lwe_key_from_binary_secret(lwe_dimension, bits) {
    Ok(value) => value
    Err(_) => return Err(InvalidCiphertext)
  }
  let mask_rng = match @random.secure_encryption_mask_rng_new() {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let noise_rng = match @random.secure_encryption_noise_rng_new() {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let serialization_rng = match
    @random.secure_rng_new_for(@random.serialization_nonce_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let encryption_noise = if parameters.test_only {
    @random.test_zero_noise_fixture()
  } else if parameters.security.target_security_bits() == 110 {
    @random.gaussian_boolean_110_lwe_fixture()
  } else {
    @random.gaussian_boolean_128_lwe_fixture()
  }
  Ok({
    inner: secret,
    mask_rng,
    noise_rng,
    serialization_rng,
    encryption_noise,
    parameters,
    key_id,
  })
}

///|
/// Serialize the public evaluation material using the versioned MBKS format.
pub fn ServerKey::serialize(
  self : ServerKey,
) -> Result[Bytes, SerializationError] {
  let bsk = match self.inner.coefficient_bsk_copy() {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  let ksk = match self.inner.key_switch_flat_copy() {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  let word_count = match
    boolean_checked_add(bsk.length(), ksk.length(), 96 * 1024 * 1024) {
    Some(value) => value
    None => return Err(InvalidLength)
  }
  let payload_length = match
    boolean_checked_mul(word_count, 4, 384 * 1024 * 1024) {
    Some(value) => value
    None => return Err(InvalidLength)
  }
  let header_length = 90
  let total_length = match
    boolean_checked_add(header_length, payload_length, 384 * 1024 * 1024) {
    Some(value) => value
    None => return Err(InvalidLength)
  }
  let output = Array::make(total_length, b'\x00')
  output[0] = b'M'
  output[1] = b'B'
  output[2] = b'K'
  output[3] = b'S'
  output[4] = b'\x02'
  output[5] = boolean_packed_layout_id()
  boolean_write_parameter_fields(output, self.parameters)
  boolean_write_key_id(output, 46, self.key_id)
  boolean_write_u32(
    output,
    62,
    match self.inner.order() {
      KeyswitchBootstrap => 0U
      BootstrapKeyswitch => 1U
    },
  )
  boolean_write_u32(
    output,
    66,
    self.inner.key_switch_input_dimension().value().reinterpret_as_uint(),
  )
  boolean_write_u32(
    output,
    70,
    self.inner.key_switch_output_dimension().value().reinterpret_as_uint(),
  )
  boolean_write_u32(output, 74, bsk.length().reinterpret_as_uint())
  boolean_write_u32(output, 78, ksk.length().reinterpret_as_uint())
  boolean_write_u32(output, 82, payload_length.reinterpret_as_uint())
  for index in 0..<bsk.length() {
    boolean_write_u32(output, header_length + index * 4, bsk[index])
  }
  let ksk_offset = header_length + bsk.length() * 4
  for index in 0..<ksk.length() {
    boolean_write_u32(output, ksk_offset + index * 4, ksk[index])
  }
  boolean_write_u32(
    output,
    86,
    boolean_crc32c_envelope_array(output, 86, header_length, payload_length),
  )
  Ok(Bytes::from_array(output))
}

///|
/// Deserialize complete, public MBKS v2 evaluation material. Fourier state is
/// intentionally absent from the format and rebuilt by the active backend.
pub fn ServerKey::deserialize(
  bytes : Bytes,
) -> Result[ServerKey, SerializationError] {
  let header_length = 90
  if bytes.length() < header_length {
    return Err(InvalidLength)
  }
  if bytes[0] != b'M' ||
    bytes[1] != b'B' ||
    bytes[2] != b'K' ||
    bytes[3] != b'S' {
    return Err(InvalidMagic)
  }
  if bytes[4] != b'\x02' {
    return Err(UnsupportedVersion)
  }
  if bytes[5] != boolean_packed_layout_id() {
    return Err(InvalidServerKey)
  }
  let parameters = match
    boolean_parameters_from_code(
      boolean_read_u32(bytes, 6).reinterpret_as_int(),
    ) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !boolean_validate_parameter_fields(bytes, parameters) {
    return Err(ParameterMismatch)
  }
  let order = match boolean_read_u32(bytes, 62) {
    0U => @pbs.keyswitch_bootstrap_order()
    1U => @pbs.bootstrap_keyswitch_order()
    _ => return Err(InvalidServerKey)
  }
  let input_dimension = parameters.record.lwe_dimension()
  let glwe = match
    @glwe.glwe_parameters(
      parameters.record.glwe_dimension().value(),
      parameters.record.polynomial_size().value(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  let ggsw = match
    @ggsw.ggsw_parameters(
      glwe,
      parameters.record.pbs_decomposition().base_log(),
      parameters.record.pbs_decomposition().level(),
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  let extracted_dimension = match
    @params.lwe_dimension(glwe.glwe_dimension() * glwe.polynomial_size()) {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  if boolean_read_u32(bytes, 66).reinterpret_as_int() !=
    extracted_dimension.value() ||
    boolean_read_u32(bytes, 70).reinterpret_as_int() != input_dimension.value() {
    return Err(ParameterMismatch)
  }
  let expected_bsk_words = match
    boolean_checked_mul(
      input_dimension.value(),
      ggsw.flat_size(),
      96 * 1024 * 1024,
    ) {
    Some(value) => value
    None => return Err(InvalidServerKey)
  }
  let expected_ksk_rows = match
    boolean_checked_mul(
      extracted_dimension.value(),
      parameters.record.ks_decomposition().level(),
      96 * 1024 * 1024,
    ) {
    Some(value) => value
    None => return Err(InvalidServerKey)
  }
  let expected_ksk_words = match
    boolean_checked_mul(
      expected_ksk_rows,
      input_dimension.value() + 1,
      96 * 1024 * 1024,
    ) {
    Some(value) => value
    None => return Err(InvalidServerKey)
  }
  let bsk_words = boolean_read_u32(bytes, 74).reinterpret_as_int()
  let ksk_words = boolean_read_u32(bytes, 78).reinterpret_as_int()
  if bsk_words != expected_bsk_words || ksk_words != expected_ksk_words {
    return Err(InvalidServerKey)
  }
  let word_count = match
    boolean_checked_add(bsk_words, ksk_words, 96 * 1024 * 1024) {
    Some(value) => value
    None => return Err(InvalidLength)
  }
  let payload_length = match
    boolean_checked_mul(word_count, 4, 384 * 1024 * 1024) {
    Some(value) => value
    None => return Err(InvalidLength)
  }
  if boolean_read_u32(bytes, 82).reinterpret_as_int() != payload_length ||
    bytes.length() != header_length + payload_length {
    return Err(InvalidLength)
  }
  if boolean_crc32c_envelope(bytes, 86, header_length, payload_length) !=
    boolean_read_u32(bytes, 86) {
    return Err(ChecksumMismatch)
  }
  let coefficient_bsk = FixedArray::makei(bsk_words, fn(index) {
    boolean_read_u32(bytes, header_length + index * 4)
  })
  let ksk_offset = header_length + bsk_words * 4
  let key_switch_data = FixedArray::makei(ksk_words, fn(index) {
    boolean_read_u32(bytes, ksk_offset + index * 4)
  })
  let bootstrap = match
    rebuild_bootstrap_key(
      parameters, input_dimension, glwe, ggsw, coefficient_bsk, extracted_dimension,
      key_switch_data, order,
    ) {
    Ok(value) => value
    Err(_) => return Err(InvalidServerKey)
  }
  Ok({ inner: bootstrap, parameters, key_id: boolean_read_key_id(bytes, 46) })
}
