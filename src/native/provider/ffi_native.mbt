///|
extern "c" fn fft_plan_new_ffi(
  size : Int,
  digit_capacity : Int,
  output_capacity : Int,
) -> NativeFftPlan = "moonbit_tfhe_fft_plan_new"

///|
#borrow(plan)
extern "c" fn fft_plan_valid_ffi(plan : NativeFftPlan) -> Bool = "moonbit_tfhe_fft_plan_valid"

///|
#borrow(plan, left, right, output)
extern "c" fn fft_plan_multiply_ffi(
  plan : NativeFftPlan,
  left : FixedArray[UInt],
  right : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Int = "moonbit_tfhe_fft_plan_multiply"

///|
#borrow(plan, left, right, output)
extern "c" fn fft_plan_batched_convolution_ffi(
  plan : NativeFftPlan,
  left : FixedArray[UInt],
  right : FixedArray[UInt],
  term_count : Int,
  output : FixedArray[UInt],
) -> Int = "moonbit_tfhe_fft_plan_batched_convolution"

///|
#borrow(plan, coefficients)
extern "c" fn fourier_bsk_new_ffi(
  plan : NativeFftPlan,
  coefficients : FixedArray[UInt],
  ggsw_count : Int,
  digit_count : Int,
  output_count : Int,
) -> NativeFourierBootstrapKey = "moonbit_tfhe_fourier_bsk_new"

///|
#borrow(key)
extern "c" fn fourier_bsk_valid_ffi(key : NativeFourierBootstrapKey) -> Bool = "moonbit_tfhe_fourier_bsk_valid"

///|
#borrow(plan, key, digits, output)
extern "c" fn fourier_bsk_external_product_ffi(
  plan : NativeFftPlan,
  key : NativeFourierBootstrapKey,
  ggsw_index : Int,
  digits : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Int = "moonbit_tfhe_fourier_bsk_external_product"

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
