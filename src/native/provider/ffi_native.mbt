///|
extern "c" fn fft_plan_new_ffi(size : Int) -> NativeFftPlan = "moonbit_tfhe_fft_plan_new"

///|
#borrow(plan)
extern "c" fn fft_plan_valid_ffi(plan : NativeFftPlan) -> Bool = "moonbit_tfhe_fft_plan_valid"

///|
#borrow(plan, left, right)
extern "c" fn fft_plan_multiply_ffi(
  plan : NativeFftPlan,
  left : Bytes,
  right : Bytes,
) -> Bytes = "moonbit_tfhe_fft_plan_multiply"

///|
#borrow(key, nonce, aad, plaintext)
extern "c" fn aes256_gcm_encrypt_ffi(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes = "moonbit_tfhe_aes256_gcm_encrypt"

///|
#borrow(key, nonce, aad, ciphertext_and_tag)
extern "c" fn aes256_gcm_decrypt_ffi(
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_and_tag : Bytes,
) -> Bytes = "moonbit_tfhe_aes256_gcm_decrypt"
