///|
/// Parameter metadata owned by the stable Boolean facade.
pub struct BooleanParameters {
  id : String
  security_bits : Int
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
} derive(Debug, Eq)

///|
pub suberror SerializationError {
  InvalidMagic
  UnsupportedVersion
  InvalidLength
  ParameterMismatch
  ChecksumMismatch
  InvalidCiphertext
} derive(Debug, Eq)

///|
/// Opaque Boolean ciphertext.
pub struct Ciphertext {
  inner : @src.BooleanCiphertext
  key_id : Int
  parameters : BooleanParameters
}

///|
/// Client-side secret key. The secret representation is owned by the core
/// package and is not exposed through this facade.
pub struct ClientKey {
  inner : @src.ExperimentalBooleanClientKey
  parameters : BooleanParameters
  key_id : Int
}

///|
/// Secret-free evaluation key.
pub struct ServerKey {
  inner : @src.ExperimentalBooleanServerKey
  parameters : BooleanParameters
  key_id : Int
}

///|
pub fn boolean_110_parameters() -> BooleanParameters {
  let record = @params.boolean_110_reference()
  {
    id: "tfhe-rs-boolean-110-reference".to_string(),
    security_bits: 110,
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
    security_bits: 128,
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
    security_bits: 0,
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
  self.security_bits
}

///|
pub fn BooleanParameters::is_test_only(self : BooleanParameters) -> Bool {
  self.test_only
}

///|
/// Production key generation is intentionally unavailable until B2 wires the
/// secure entropy provider into the core encryption path.
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
  let (client, server) = @src.experimental_boolean_keygen(seed)
  // The current experimental implementation derives the tag internally. The
  // facade uses the deterministic seed as its compatibility identity.
  let key_id = seed.to_int()
  let client_key : ClientKey = { inner: client, parameters, key_id }
  let server_key : ServerKey = { inner: server, parameters, key_id }
  Ok((client_key, server_key))
}

///|
pub fn ClientKey::encrypt(self : ClientKey, message : Bool) -> Ciphertext {
  {
    inner: self.inner.encrypt(message),
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
  match self.inner.decrypt(ciphertext.inner) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
fn evaluate_check(
  parameters : BooleanParameters,
  key_id : Int,
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
  match self.inner.not(ciphertext.inner) {
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
  match self.inner.nand(left.inner, right.inner) {
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
/// The generic LUT surface is reserved until the production PBS path supports
/// arbitrary torus tables. Returning a typed error prevents callers from
/// accidentally assuming the current two-point Boolean prototype is generic.
pub fn ServerKey::apply_lut(
  _self : ServerKey,
  _ciphertext : Ciphertext,
  _table : Array[Bool],
) -> Result[Ciphertext, EvaluationError] {
  Err(UnsupportedLut)
}

///|
pub fn Ciphertext::serialize(self : Ciphertext) -> Bytes {
  let payload = self.inner.serialize()
  let output = Array::make(25 + payload.length(), b'\x00')
  output[0] = b'M'
  output[1] = b'B'
  output[2] = b'C'
  output[3] = b'T'
  output[4] = b'\x01'
  boolean_write_i32(output, 5, boolean_parameter_code(self.parameters))
  boolean_write_i32(output, 9, self.parameters.dimension)
  boolean_write_i32(output, 13, self.key_id)
  boolean_write_i32(output, 17, payload.length())
  boolean_write_i32(output, 21, boolean_checksum(payload))
  for i in 0..<payload.length() {
    output[25 + i] = payload[i]
  }
  Bytes::from_array(output)
}

///|
pub fn ClientKey::deserialize(
  self : ClientKey,
  bytes : Bytes,
) -> Result[Ciphertext, SerializationError] {
  if bytes.length() < 25 {
    return Err(InvalidLength)
  }
  if bytes[0] != b'M' ||
    bytes[1] != b'B' ||
    bytes[2] != b'C' ||
    bytes[3] != b'T' {
    return Err(InvalidMagic)
  }
  if bytes[4] != b'\x01' {
    return Err(UnsupportedVersion)
  }
  let parameter_code = boolean_read_i32(bytes, 5)
  if parameter_code != boolean_parameter_code(self.parameters) {
    return Err(ParameterMismatch)
  }
  let dimension = boolean_read_i32(bytes, 9)
  if dimension != self.parameters.dimension {
    return Err(ParameterMismatch)
  }
  let key_id = boolean_read_i32(bytes, 13)
  if key_id != self.key_id {
    return Err(ParameterMismatch)
  }
  let payload_length = boolean_read_i32(bytes, 17)
  if payload_length < 0 || bytes.length() != 25 + payload_length {
    return Err(InvalidLength)
  }
  let expected_checksum = boolean_read_i32(bytes, 21)
  let payload = bytes[25:].to_owned()
  if boolean_checksum(payload) != expected_checksum {
    return Err(ChecksumMismatch)
  }
  match self.inner.deserialize_ciphertext(payload) {
    Ok(value) =>
      Ok({ inner: value, key_id: self.key_id, parameters: self.parameters })
    Err(_) => Err(InvalidCiphertext)
  }
}

///|
fn boolean_parameter_code(parameters : BooleanParameters) -> Int {
  if parameters.test_only {
    0
  } else if parameters.security_bits == 110 {
    110
  } else {
    128
  }
}

///|
fn boolean_write_i32(output : Array[Byte], offset : Int, value : Int) -> Unit {
  output[offset] = value.to_byte()
  output[offset + 1] = (value >> 8).to_byte()
  output[offset + 2] = (value >> 16).to_byte()
  output[offset + 3] = (value >> 24).to_byte()
}

///|
fn boolean_read_i32(input : Bytes, offset : Int) -> Int {
  input[offset].to_int() |
  (input[offset + 1].to_int() << 8) |
  (input[offset + 2].to_int() << 16) |
  (input[offset + 3].to_int() << 24)
}

///|
fn boolean_checksum(bytes : Bytes) -> Int {
  let mut hash = 0x811C9DC5
  for byte in bytes {
    hash = (hash ^ byte.to_int()) * 0x01000193
  }
  hash
}
