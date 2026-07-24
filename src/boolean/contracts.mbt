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
