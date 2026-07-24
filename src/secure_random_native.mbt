///|
extern "c" fn secure_random_available() -> Bool = "moonbit_tfhe_secure_random_available"

///|
extern "c" fn secure_random_u64() -> UInt64 = "moonbit_tfhe_secure_random_u64"

///|
fn secure_rng_backend_available() -> Bool {
  secure_random_available()
}

///|
fn secure_rng_backend_next() -> UInt64 {
  secure_random_u64()
}
