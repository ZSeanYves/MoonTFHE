///|
/// JS host entropy is intentionally disabled until a crypto.getRandomValues
/// adapter is wired with an explicit FFI contract.
fn secure_rng_backend_available() -> Bool {
  false
}

///|
fn secure_rng_backend_next() -> UInt64 {
  0UL
}
