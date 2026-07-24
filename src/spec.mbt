///|
/// Contract surface for the public experimental facade. The declarations are
/// intentionally opaque: callers can encrypt/decrypt and apply NOT, but cannot
/// construct or inspect ciphertext representation.
declare pub type ExperimentalClientKey

///|
declare pub type ExperimentalCiphertext

///|
declare pub fn experimental_keygen(
  dimension : Int,
  sigma : Float,
  seed : UInt64,
) -> ExperimentalClientKey

///|
declare pub fn ExperimentalClientKey::encrypt(
  self : ExperimentalClientKey,
  message : Bool,
) -> ExperimentalCiphertext

///|
declare pub fn ExperimentalClientKey::decrypt(
  self : ExperimentalClientKey,
  ciphertext : ExperimentalCiphertext,
) -> Bool

///|
declare pub fn ExperimentalCiphertext::not(
  self : ExperimentalCiphertext,
) -> ExperimentalCiphertext
