///|
declare pub type BooleanParameters

///|
declare pub type Backend

///|
declare pub type SerializationKey

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
declare pub fn ServerKey::xor_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::xnor_gate(
  self : ServerKey,
  left : Ciphertext,
  right : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::mux(
  self : ServerKey,
  selector : Ciphertext,
  when_true : Ciphertext,
  when_false : Ciphertext,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::apply_lut(
  self : ServerKey,
  ciphertext : Ciphertext,
  table : Array[Bool],
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn ServerKey::evaluation_context(
  self : ServerKey,
) -> EvaluationContext

///|
declare pub fn programmable_bootstrap_lut(
  parameters : BooleanParameters,
  values : Array[@torus.Torus32],
) -> Result[ProgrammableBootstrapLut, LutError]

///|
declare pub fn ServerKey::apply_programmable_lut(
  self : ServerKey,
  ciphertext : Ciphertext,
  lut : ProgrammableBootstrapLut,
) -> Result[Ciphertext, EvaluationError]

///|
declare pub fn Ciphertext::serialize(self : Ciphertext) -> Bytes

///|
declare pub fn ClientKey::deserialize(
  self : ClientKey,
  bytes : Bytes,
) -> Result[Ciphertext, SerializationError]

///|
declare pub fn ClientKey::export_secret(
  self : ClientKey,
  key : SerializationKey,
) -> Result[Bytes, SerializationError]

///|
declare pub fn ClientKey::import_secret(
  parameters : BooleanParameters,
  key : SerializationKey,
  bytes : Bytes,
) -> Result[ClientKey, SerializationError]

///|
declare pub fn ServerKey::serialize(
  self : ServerKey,
) -> Result[Bytes, SerializationError]

///|
declare pub fn ServerKey::deserialize(
  bytes : Bytes,
) -> Result[ServerKey, SerializationError]
