///|
test "portable provider: no native fallback" {
  assert_true(fft_plan_new(4) is Err(UnsupportedBackend))
  assert_true(
    aes256_gcm_encrypt(
      Bytes::make(32, 0),
      Bytes::make(12, 0),
      Bytes::make(0, 0),
      Bytes::make(0, 0),
    )
    is Err(UnsupportedBackend),
  )
}
