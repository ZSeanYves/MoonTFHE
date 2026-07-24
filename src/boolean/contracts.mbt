///|
/// Backend selected by the Boolean facade.
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
pub type AeadEncryptProvider = (Bytes, Bytes, Bytes) -> Result[
  Bytes,
  BackendError,
]

///|
let aead_encrypt_provider : Ref[AeadEncryptProvider?] = @ref.new(None)

///|
pub fn install_aead_encrypt_provider(provider : AeadEncryptProvider) -> Unit {
  aead_encrypt_provider.val = Some(provider)
}

///|
pub fn clear_aead_encrypt_provider() -> Unit {
  aead_encrypt_provider.val = None
}

///|
pub suberror BackendError {
  UnsupportedBackend(backend~ : Backend)
  EntropyUnavailable
  InvalidProviderOutput
} derive(Debug, Eq)

///|
pub fn Backend::name(self : Backend) -> String {
  match self {
    Native => "native"
    JavaScript => "js"
    Wasm => "wasm"
    WasmGc => "wasm-gc"
  }
}
