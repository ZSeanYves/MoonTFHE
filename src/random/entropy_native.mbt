///|
extern "c" fn entropy_available() -> Bool = "moonbit_tfhe_entropy_available"

///|
extern "c" fn entropy_u32() -> UInt = "moonbit_tfhe_entropy_u32"

///|
fn entropy_backend_available() -> Bool {
  entropy_available()
}

///|
fn entropy_backend_u32() -> UInt {
  entropy_u32()
}
