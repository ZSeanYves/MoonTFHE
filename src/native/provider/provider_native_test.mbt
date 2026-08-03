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
  let left : FixedArray[UInt] = [0xffff0001, 0x80000000, 7, 0x12345678]
  let right : FixedArray[UInt] = [0x0001ffff, 3, 0x80000001, 11]
  let first = FixedArray::make(4, 0U)
  let second = FixedArray::make(4, 0U)
  plan.negacyclic_mul_u32(left, right, first).unwrap()
  plan.negacyclic_mul_u32(left, right, second).unwrap()
  assert_eq(first, second)
  assert_eq(first.length(), 4)
  assert_true(
    plan.negacyclic_mul_u32(
      FixedArray::make(3, 0U),
      FixedArray::make(3, 0U),
      FixedArray::make(3, 0U),
    )
    is Err(InvalidLength),
  )
}

///|
test "native provider: Fourier BSK indexed external product is reusable" {
  let n = 4
  let plan = fft_plan_new_with_capacity(n, 2, 2).unwrap()
  let coefficients = FixedArray::makei(2 * 2 * 2 * n, fn(index) {
    (index.reinterpret_as_uint() * 0x9e3779b9U) ^ 0xf0000001U
  })
  let key = fourier_bsk_new(plan, coefficients, 2, 2, 2).unwrap()
  let digits : FixedArray[UInt] = [1, 0xffffffff, 2, 0, 3, 0xfffffffe, 1, 0]
  let first = FixedArray::make(2 * n, 0U)
  let second = FixedArray::make(2 * n, 0U)
  key.external_product(1, digits, first).unwrap()
  key.external_product(1, digits, second).unwrap()
  assert_eq(first, second)
  let addend = FixedArray::make(2 * n, 0x80000001U)
  let fused = FixedArray::make(2 * n, 0U)
  key.blind_rotation_step(1, digits, addend, fused).unwrap()
  for index in 0..<fused.length() {
    assert_eq(fused[index], first[index] + addend[index])
  }
  let batch_digits = FixedArray::makei(digits.length() * 2, fn(index) {
    digits[index % digits.length()]
  })
  let batch_output = FixedArray::make(4 * n, 0U)
  key.external_product_batch([0U, 1U], batch_digits, batch_output).unwrap()
  for index in 0..<second.length() {
    assert_eq(batch_output[second.length() + index], second[index])
  }
  fourier_accumulator_add_in_place(first, addend).unwrap()
  assert_eq(first, fused)
  plan.workspace_reset().unwrap()
  assert_true(key.external_product(2, digits, second) is Err(InvalidLength))
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
