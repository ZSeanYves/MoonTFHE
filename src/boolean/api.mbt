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
} derive(Debug, Eq)

///|
/// Opaque Boolean ciphertext.
pub struct Ciphertext {
  inner : @src.BooleanCiphertext
  key_id : Int
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
  { inner: self.inner.encrypt(message), key_id: self.key_id }
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
    Ok(value) => Ok({ inner: value, key_id: self.key_id })
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
    Ok(value) => Ok({ inner: value, key_id: self.key_id })
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
pub fn Ciphertext::serialize(self : Ciphertext) -> Bytes {
  self.inner.serialize()
}

///|
pub fn ClientKey::deserialize(
  self : ClientKey,
  bytes : Bytes,
) -> Result[Ciphertext, DecryptionError] {
  match self.inner.deserialize_ciphertext(bytes) {
    Ok(value) => Ok({ inner: value, key_id: self.key_id })
    Err(_) => Err(InvalidCiphertext)
  }
}
