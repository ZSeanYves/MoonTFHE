///|
/// A deterministic, insecure client key for examples and regression tests.
///
/// This API uses a reproducible non-cryptographic generator. It must not be
/// used with sensitive data. The production API introduced in later roadmap
/// phases uses a separate secure randomness type.
pub struct ExperimentalClientKey {
  key : LweKey
  rng : CsPrng
  sigma : Float
}

///|
/// An opaque LWE ciphertext owned by the experimental facade.
pub struct ExperimentalCiphertext {
  inner : LweCiphertext
}

///|
/// Generate a deterministic experimental client key.
pub fn experimental_keygen(
  dimension : Int,
  sigma : Float,
  seed : UInt64,
) -> ExperimentalClientKey {
  let rng = csprng_new(seed)
  { key: lwe_key_new(dimension, rng), rng, sigma }
}

///|
/// Encrypt one Boolean value with an experimental client key.
pub fn ExperimentalClientKey::encrypt(
  self : ExperimentalClientKey,
  message : Bool,
) -> ExperimentalCiphertext {
  { inner: lwe_encrypt(self.key, message, self.sigma, self.rng) }
}

///|
/// Decrypt one experimental Boolean ciphertext.
pub fn ExperimentalClientKey::decrypt(
  self : ExperimentalClientKey,
  ciphertext : ExperimentalCiphertext,
) -> Bool {
  lwe_decrypt(self.key, ciphertext.inner)
}

///|
/// Evaluate Boolean NOT by negating the LWE phase. No secret key is used.
pub fn ExperimentalCiphertext::not(
  self : ExperimentalCiphertext,
) -> ExperimentalCiphertext {
  { inner: lwe_ct_scale(self.inner, -1) }
}
