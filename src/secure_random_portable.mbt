///|
/// Browser/wasm hosts must provide an entropy adapter before this backend is
/// suitable for production. Returning UnsupportedBackend is safer than
/// silently falling back to the legacy deterministic generator.
fn secure_rng_backend_available() -> Bool {
  false
}

///|
fn secure_rng_backend_next() -> UInt64 {
  0UL
}
