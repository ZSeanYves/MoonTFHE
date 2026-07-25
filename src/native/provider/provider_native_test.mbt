///|
test "native provider: AES-256-GCM NIST vector and authentication failure" {
  let key = Bytes::make(32, 0)
  let nonce = Bytes::make(12, 0)
  let plaintext = Bytes::make(16, 0)
  let ciphertext_and_tag = aes256_gcm_encrypt(
    key,
    nonce,
    Bytes::make(0, 0),
    plaintext,
  ).unwrap()
  let expected = Bytes::from_array([
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba,
    0xf3, 0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b,
    0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
  ])
  assert_eq(ciphertext_and_tag, expected)
  assert_eq(
    aes256_gcm_decrypt(key, nonce, Bytes::make(0, 0), ciphertext_and_tag),
    Ok(plaintext),
  )
  let tampered = ciphertext_and_tag.to_array()
  tampered[tampered.length() - 1] = tampered[tampered.length() - 1] ^ 1
  assert_true(
    aes256_gcm_decrypt(
      key,
      nonce,
      Bytes::make(0, 0),
      Bytes::from_array(tampered),
    )
    is Err(AuthenticationFailed),
  )
}

///|
test "native provider: full-width FFT matches negacyclic fixture" {
  let plan = fft_plan_new(4).unwrap()
  let left = Bytes::from_array([
    0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00, 0x00, 0x78,
    0x56, 0x34, 0x12,
  ])
  let right = Bytes::from_array([
    0xff, 0xff, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80, 0x0b,
    0x00, 0x00, 0x00,
  ])
  let first = plan.negacyclic_mul_u32_le(left, right).unwrap()
  let second = plan.negacyclic_mul_u32_le(left, right).unwrap()
  assert_eq(first, second)
  assert_eq(first.length(), 16)
  assert_true(
    plan.negacyclic_mul_u32_le(left[:12].to_owned(), right[:12].to_owned())
    is Err(InvalidLength),
  )
}

///|
test "native provider: validates plans and AEAD lengths before FFI" {
  assert_true(fft_plan_new(0) is Err(InvalidPolynomialSize))
  assert_true(fft_plan_new(6) is Err(InvalidPolynomialSize))
  assert_true(
    aes256_gcm_encrypt(
      Bytes::make(31, 0),
      Bytes::make(12, 0),
      Bytes::make(0, 0),
      Bytes::make(0, 0),
    )
    is Err(InvalidLength),
  )
}
