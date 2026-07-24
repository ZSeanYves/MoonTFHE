///|
extern "js" fn web_crypto_fill(buffer : Bytes) -> Bool =
  #| (buffer) => {
  #|   const crypto = globalThis.crypto;
  #|   if (!crypto || typeof crypto.getRandomValues !== "function") {
  #|     return false;
  #|   }
  #|   crypto.getRandomValues(buffer);
  #|   return true;
  #| }

///|
fn entropy_backend_bytes(count : Int) -> Bytes? {
  let buffer = Bytes::make(count, 0)
  if web_crypto_fill(buffer) {
    Some(buffer)
  } else {
    None
  }
}
