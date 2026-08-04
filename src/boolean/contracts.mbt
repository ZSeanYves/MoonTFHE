///|
/// Backend selected by the Boolean facade.
#warnings("-unused_constructor")
pub enum Backend {
  Native
  JavaScript
  Wasm
  WasmGc
} derive(Debug, Eq)

///|
/// A caller-owned 256-bit key used only by explicit SecretExport APIs.
///
/// The constructor is intentionally not public yet. C5 will add validation and
/// AES-256-GCM backed import/export without accepting passwords or implicit
/// derivation.
pub struct SerializationKey {
  bytes : Bytes
}

///|
pub suberror SerializationKeyError {
  InvalidLength
} derive(Debug, Eq)

///|
/// Construct a key for explicit AES-256-GCM SecretExport.
/// Passwords and implicit key derivation are intentionally not supported.
pub fn serialization_key_from_bytes(
  bytes : Bytes,
) -> Result[SerializationKey, SerializationKeyError] {
  if bytes.length() != 32 {
    Err(InvalidLength)
  } else {
    Ok({ bytes, })
  }
}

///|
/// Host-provided AES-GCM boundary. The provider must generate a fresh secure
/// nonce and return a versioned envelope containing nonce||ciphertext||tag.
/// A missing provider is an explicit error.
pub type AeadEncryptProvider = (Bytes, Bytes, Bytes, Bytes) -> Result[
  Bytes,
  BackendError,
]

///|
/// Host-provided AES-GCM decryption. The final argument is ciphertext||tag;
/// providers must authenticate before returning plaintext.
pub type AeadDecryptProvider = (Bytes, Bytes, Bytes, Bytes) -> Result[
  Bytes,
  BackendError,
]

///|
let aead_encrypt_provider : Ref[AeadEncryptProvider?] = @ref.new(None)

///|
let aead_decrypt_provider : Ref[AeadDecryptProvider?] = @ref.new(None)

///|
pub fn install_aead_encrypt_provider(provider : AeadEncryptProvider) -> Unit {
  aead_encrypt_provider.val = Some(provider)
}

///|
pub fn clear_aead_encrypt_provider() -> Unit {
  aead_encrypt_provider.val = None
}

///|
pub fn install_aead_decrypt_provider(provider : AeadDecryptProvider) -> Unit {
  aead_decrypt_provider.val = Some(provider)
}

///|
pub fn clear_aead_decrypt_provider() -> Unit {
  aead_decrypt_provider.val = None
}

///|
#warnings("-unused_constructor")
pub suberror BackendError {
  UnsupportedBackend(backend~ : Backend)
  EntropyUnavailable
  InvalidProviderOutput
} derive(Debug, Eq)

///|
fn boolean_aead_encrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Result[Bytes, BackendError] {
  match aead_encrypt_provider.val {
    Some(provider) => provider(key, nonce, aad, plaintext)
    None =>
      match @provider.aes256_gcm_encrypt(key, nonce, aad, plaintext) {
        Ok(value) => Ok(value)
        Err(UnsupportedBackend) => Err(UnsupportedBackend(backend=backend()))
        Err(InvalidLength) => Err(InvalidProviderOutput)
        Err(InvalidPolynomialSize) => Err(InvalidProviderOutput)
        Err(AuthenticationFailed) => Err(InvalidProviderOutput)
        Err(ProviderFailure(_)) => Err(InvalidProviderOutput)
      }
  }
}

///|
fn boolean_aead_decrypt(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_and_tag : Bytes,
) -> Result[Bytes, BackendError] {
  match aead_decrypt_provider.val {
    Some(provider) => provider(key, nonce, aad, ciphertext_and_tag)
    None =>
      match @provider.aes256_gcm_decrypt(key, nonce, aad, ciphertext_and_tag) {
        Ok(value) => Ok(value)
        Err(UnsupportedBackend) => Err(UnsupportedBackend(backend=backend()))
        Err(InvalidLength) => Err(InvalidProviderOutput)
        Err(InvalidPolynomialSize) => Err(InvalidProviderOutput)
        Err(AuthenticationFailed) => Err(InvalidProviderOutput)
        Err(ProviderFailure(_)) => Err(InvalidProviderOutput)
      }
  }
}

///|
pub fn Backend::name(self : Backend) -> String {
  match self {
    Native => "native"
    JavaScript => "js"
    Wasm => "wasm"
    WasmGc => "wasm-gc"
  }
}
