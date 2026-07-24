///|
// The C stub fills the caller-owned MoonBit byte buffer from the OS RNG.
#borrow(buffer)
extern "c" fn entropy_read(buffer : Bytes) -> Int = "moonbit_tfhe_entropy_read"

///|
fn entropy_backend_bytes(count : Int) -> Bytes? {
  let buffer = Bytes::make(count, 0)
  if entropy_read(buffer) == 0 {
    Some(buffer)
  } else {
    None
  }
}
