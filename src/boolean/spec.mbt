///|
declare pub type BooleanParameters

///|
declare pub type ClientKey

///|
declare pub type ServerKey

///|
declare pub type Ciphertext

///|
declare pub fn boolean_110_parameters() -> BooleanParameters

///|
declare pub fn boolean_128_parameters() -> BooleanParameters

///|
declare pub fn boolean_test_parameters() -> BooleanParameters

///|
declare pub fn generate_keys(
  parameters : BooleanParameters,
) -> Result[(ClientKey, ServerKey), KeyGenerationError]

///|
declare pub fn generate_test_keys(
  parameters : BooleanParameters,
  seed : UInt64,
) -> Result[(ClientKey, ServerKey), KeyGenerationError]

///|
declare pub fn ClientKey::encrypt(
  self : ClientKey,
  message : Bool,
) -> Ciphertext

///|
declare pub fn ClientKey::decrypt(
  self : ClientKey,
  ciphertext : Ciphertext,
) -> Result[Bool, DecryptionError]

///|
declare pub fn ServerKey::nand(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::not(
  self : ServerKey,
  ciphertext : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::and_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::or_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn Ciphertext::serialize(self : Ciphertext) -> Bytes
