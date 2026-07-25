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
pub suberror EvaluationError {
  KeyMismatch
  InvalidCiphertext
  UnsupportedLut
  InvalidLutLength
} derive(Debug, Eq)

///|
pub suberror SerializationError {
  InvalidMagic
  UnsupportedVersion
  InvalidLength
  ParameterMismatch
  ChecksumMismatch
  InvalidCiphertext
  InvalidKeyLength
  AuthenticationFailed
  UnsupportedBackend
} derive(Debug, Eq)

///|
/// Opaque Boolean ciphertext.
pub struct Ciphertext {
  inner : @lwe.LweCiphertext
  key_id : @params.KeyId
  parameters : BooleanParameters
}

///|
/// Client-side secret key. The secret representation is owned by the core
/// package and is not exposed through this facade.
pub struct ClientKey {
  inner : @lwe.LweSecretKey
  rng : @random.RandomGenerator
  parameters : BooleanParameters
  key_id : @params.KeyId
}

///|
/// Secret-free evaluation key.
pub struct ServerKey {
  inner : @pbs.BootstrapKey
  parameters : BooleanParameters
  key_id : @params.KeyId
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
/// Production key generation remains unavailable during C0/C1. The error is
/// intentional until the migrated core owns the full entropy and PBS path.
pub fn generate_keys(
  parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError] {
  if parameters.test_only || parameters.dimension <= 0 {
    return Err(InvalidParameters)
  }
  if parameters.record.validate() is Err(_) {
    return Err(InvalidParameters)
  }
  Err(UnsupportedBackend)
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
  let input_dimension = @params.lwe_dimension(parameters.dimension).unwrap()
  let glwe = @glwe.glwe_parameters(
    parameters.record.glwe_dimension().value(),
    parameters.record.polynomial_size().value(),
  ).unwrap()
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
  let glwe_key = @glwe.glwe_key_from_binary_secret(glwe, glwe_data).unwrap()
  let extracted_key = glwe_key.to_extracted_lwe_key().unwrap()
  let noise = @random.test_zero_noise_fixture()
  let key_switch = @keyswitch.keyswitch_keygen(
    extracted_key,
    input_key,
    parameters.record.ks_decomposition(),
    noise,
    @random.test_rng_new(seed ^ 0x4B534BUL),
  ).unwrap()
  let ggsw_parameters = @ggsw.ggsw_parameters(
    glwe,
    parameters.record.pbs_decomposition().base_log(),
    parameters.record.pbs_decomposition().level(),
  ).unwrap()
  let controls : Array[@ggsw.GgswCiphertext] = []
  for index in 0..<input_bits.length() {
    controls.push(
      @ggsw.ggsw_encrypt_boolean(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        noise,
        @random.test_rng_new(seed ^ (0x42534B00UL + index.to_uint64())),
      ).unwrap(),
    )
  }
  let bootstrap = @pbs.bootstrap_key_from_encrypted_parts(
    input_dimension,
    glwe,
    controls,
    key_switch,
    @pbs.bootstrap_keyswitch_order(),
  ).unwrap()
  let key_id = @params.key_id_from_int(seed.to_int())
  let client_key : ClientKey = {
    inner: input_key,
    rng: @random.test_rng_new(seed ^ 0x454E43UL),
    parameters,
    key_id,
  }
  let server_key : ServerKey = { inner: bootstrap, parameters, key_id }
  Ok((client_key, server_key))
}

///|
pub fn ClientKey::encrypt(self : ClientKey, message : Bool) -> Ciphertext {
  {
    inner: self.inner
    .lwe_encrypt_binary(message, @random.test_zero_noise_fixture(), self.rng)
    .unwrap(),
    key_id: self.key_id,
    parameters: self.parameters,
  }
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
pub fn ServerKey::not(
  self : ServerKey,
  ciphertext : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  match evaluate_check(self.parameters, self.key_id, ciphertext) {
    Ok(_) => ()
    Err(error) => return Err(error)
  }
  match
    self.inner.programmable_bootstrap(
      ciphertext.inner,
      @pbs.boolean_lut(
        @torus.Torus32::from_int(0x2000_0000),
        @torus.Torus32::from_int(-0x2000_0000),
      ),
    ) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
pub fn ServerKey::nand(
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
    Ok(value) => value.sub_plain(@torus.Torus32::from_int(0x2000_0000))
    Err(_) => return Err(InvalidCiphertext)
  }
  let n = self.parameters.record.polynomial_size().value()
  let table = Array::makei(n, fn(rotation) {
    let first = n / 8
    let third = 3 * n / 8
    let fifth = 5 * n / 8
    let seventh = 7 * n / 8
    if (rotation >= first && rotation < third) ||
      (rotation >= fifth && rotation < seventh) {
      @torus.Torus32::from_int(0x2000_0000)
    } else {
      @torus.Torus32::from_int(-0x2000_0000)
    }
  })
  match self.inner.programmable_bootstrap_table(combined, table) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
pub fn ServerKey::and_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  let nand = match self.nand(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match self.not(nand) {
    Ok(value) => Ok(value)
    Err(error) => Err(error)
  }
}

///|
pub fn ServerKey::or_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  let not_left = match self.not(left) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let not_right = match self.not(right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match self.nand(not_left, not_right) {
    Ok(value) => Ok(value)
    Err(error) => Err(error)
  }
}

///|
/// Evaluate XOR using the Boolean NAND/NOT facade.
pub fn ServerKey::xor_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  let left_or_right = match self.or_gate(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let left_and_right = match self.and_gate(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match
    self.and_gate(
      left_or_right,
      match self.not(left_and_right) {
        Ok(value) => value
        Err(error) => return Err(error)
      },
    ) {
    Ok(value) => Ok(value)
    Err(error) => Err(error)
  }
}

///|
pub fn ServerKey::xnor_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  let xor = match self.xor_gate(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  self.not(xor)
}

///|
/// Select `when_true` when `selector` is true, otherwise `when_false`.
pub fn ServerKey::mux(
  self : ServerKey,
  selector : Ciphertext,
  when_true : Ciphertext,
  when_false : Ciphertext,
) -> Result[Ciphertext, EvaluationError] {
  let selected_true = match self.and_gate(selector, when_true) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let not_selector = match self.not(selector) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let selected_false = match self.and_gate(not_selector, when_false) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  self.or_gate(selected_true, selected_false)
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
  match (table[0], table[1]) {
    (false, true) => Ok(ciphertext)
    (true, false) => self.not(ciphertext)
    (false, false) => {
      let negated = match self.not(ciphertext) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      self.and_gate(ciphertext, negated)
    }
    (true, true) => {
      let negated = match self.not(ciphertext) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      self.or_gate(ciphertext, negated)
    }
  }
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
  let header_length = 39
  let output = Array::make(header_length + payload.length(), b'\x00')
  output[0] = b'M'
  output[1] = b'B'
  output[2] = b'C'
  output[3] = b'T'
  output[4] = b'\x02'
  output[5] = b'\x01'
  boolean_write_u32(
    output,
    7,
    boolean_parameter_code(self.parameters).reinterpret_as_uint(),
  )
  boolean_write_u32(output, 11, self.parameters.dimension.reinterpret_as_uint())
  boolean_write_u32(output, 15, self.key_id.to_int().reinterpret_as_uint())
  // Torus32 uses modulus 2^32, represented by zero modulo 2^32.
  boolean_write_u32(output, 19, 0U)
  // The compatibility facade has no production decomposition yet.
  boolean_write_u32(output, 23, 0U)
  boolean_write_u32(output, 27, if self.parameters.test_only { 0U } else { 1U })
  boolean_write_u32(output, 31, payload.length().reinterpret_as_uint())
  boolean_write_u32(output, 35, boolean_crc32c(payload))
  for i in 0..<payload.length() {
    output[header_length + i] = payload[i]
  }
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
  let header_length = 39
  let mut parameter_code = 0
  let mut dimension = 0
  let mut key_id = @params.key_id_from_int(0)
  let mut payload_length = 0
  let mut payload = Bytes::make(0, 0)
  let mut checksum_ok = false
  if version != b'\x02' || bytes.length() < header_length || bytes[5] != b'\x01' {
    return Err(UnsupportedVersion)
  }
  parameter_code = boolean_read_u32(bytes, 7).reinterpret_as_int()
  dimension = boolean_read_u32(bytes, 11).reinterpret_as_int()
  key_id = @params.key_id_from_int(
    boolean_read_u32(bytes, 15).reinterpret_as_int(),
  )
  if boolean_read_u32(bytes, 19) != 0U || boolean_read_u32(bytes, 23) != 0U {
    return Err(InvalidCiphertext)
  }
  let distribution = if self.parameters.test_only { 0U } else { 1U }
  if boolean_read_u32(bytes, 27) != distribution {
    return Err(ParameterMismatch)
  }
  payload_length = boolean_read_u32(bytes, 31).reinterpret_as_int()
  if payload_length < 0 || bytes.length() != header_length + payload_length {
    return Err(InvalidLength)
  }
  payload = bytes[header_length:].to_owned()
  checksum_ok = boolean_crc32c(payload) == boolean_read_u32(bytes, 35)
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
fn boolean_write_u32(output : Array[Byte], offset : Int, value : UInt) -> Unit {
  output[offset] = value.to_byte()
  output[offset + 1] = (value >> 8).to_byte()
  output[offset + 2] = (value >> 16).to_byte()
  output[offset + 3] = (value >> 24).to_byte()
}

///|
fn boolean_read_u32(input : Bytes, offset : Int) -> UInt {
  input[offset].to_uint() |
  (input[offset + 1].to_uint() << 8) |
  (input[offset + 2].to_uint() << 16) |
  (input[offset + 3].to_uint() << 24)
}

///|
/// Castagnoli CRC32C, used by the v2 binary format.
fn boolean_crc32c(bytes : Bytes) -> UInt {
  let mut crc = 0xFFFFFFFFU
  for byte in bytes {
    crc = crc ^ byte.to_uint()
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
  let header = Array::make(22, b'\x00')
  header[0] = b'M'
  header[1] = b'T'
  header[2] = b'S'
  header[3] = b'K'
  header[4] = b'\x01'
  header[5] = b'\x01'
  boolean_write_u32(
    header,
    6,
    boolean_parameter_code(self.parameters).reinterpret_as_uint(),
  )
  boolean_write_u32(header, 10, self.parameters.dimension.reinterpret_as_uint())
  boolean_write_u32(header, 14, self.key_id.to_int().reinterpret_as_uint())
  boolean_write_u32(header, 18, payload_length.reinterpret_as_uint())
  let nonce_rng = match
    @random.secure_rng_new_for(@random.serialization_nonce_domain()) {
    Ok(value) => value
    Err(_) => return Err(UnsupportedBackend)
  }
  let nonce = Array::make(12, b'\x00')
  for word_index in 0..<3 {
    let word = nonce_rng.next_u32()
    for byte_index in 0..<4 {
      nonce[word_index * 4 + byte_index] = (word >> (byte_index * 8)).to_byte()
    }
  }
  let payload = self.inner.secret_export_payload()
  let encrypted = match
    @provider.aes256_gcm_encrypt(
      key.bytes,
      Bytes::from_array(nonce),
      Bytes::from_array(header),
      payload,
    ) {
    Ok(value) => value
    Err(@provider.NativeProviderError::UnsupportedBackend) =>
      return Err(UnsupportedBackend)
    Err(@provider.NativeProviderError::InvalidLength) =>
      return Err(InvalidLength)
    Err(@provider.NativeProviderError::InvalidPolynomialSize) =>
      return Err(InvalidLength)
    Err(@provider.NativeProviderError::AuthenticationFailed) =>
      return Err(AuthenticationFailed)
    Err(@provider.NativeProviderError::ProviderFailure(status~)) =>
      return Err(UnsupportedBackend)
  }
  if encrypted.length() != payload_length + 16 {
    return Err(InvalidLength)
  }
  let output = Array::make(34 + encrypted.length(), b'\x00')
  for index in 0..<22 {
    output[index] = header[index]
  }
  for index in 0..<12 {
    output[22 + index] = nonce[index]
  }
  for index in 0..<encrypted.length() {
    output[34 + index] = encrypted[index]
  }
  Ok(Bytes::from_array(output))
}

///|
/// Serialize the public evaluation material using the versioned MBKS format.
pub fn ServerKey::serialize(
  self : ServerKey,
) -> Result[Bytes, SerializationError] {
  // The formal public format is completed in C12. During C7 the payload is a
  // typed, secret-free structural marker rather than a legacy root snapshot.
  let payload = Bytes::from_array([
    b'M',
    b'K',
    b'S',
    b'P',
    b'\x01',
    self.parameters.dimension.to_byte(),
  ])
  let header_length = 39
  let output = Array::make(header_length + payload.length(), b'\x00')
  output[0] = b'M'
  output[1] = b'B'
  output[2] = b'K'
  output[3] = b'S'
  output[4] = b'\x01'
  output[5] = b'\x01'
  boolean_write_u32(
    output,
    7,
    boolean_parameter_code(self.parameters).reinterpret_as_uint(),
  )
  boolean_write_u32(output, 11, self.parameters.dimension.reinterpret_as_uint())
  boolean_write_u32(output, 15, self.key_id.to_int().reinterpret_as_uint())
  boolean_write_u32(output, 19, 0U)
  boolean_write_u32(output, 23, 0U)
  boolean_write_u32(output, 27, if self.parameters.test_only { 0U } else { 1U })
  boolean_write_u32(output, 31, payload.length().reinterpret_as_uint())
  boolean_write_u32(output, 35, boolean_crc32c(payload))
  for index in 0..<payload.length() {
    output[header_length + index] = payload[index]
  }
  Ok(Bytes::from_array(output))
}
