///|
test "stable Boolean facade: portable AEAD adapters are actually invoked" {
  let encrypt_calls = @ref.new(0)
  let decrypt_calls = @ref.new(0)
  install_aead_encrypt_provider(fn(_key, _nonce, _aad, plaintext) {
    encrypt_calls.val = encrypt_calls.val + 1
    Ok(plaintext)
  })
  install_aead_decrypt_provider(fn(_key, _nonce, _aad, ciphertext) {
    decrypt_calls.val = decrypt_calls.val + 1
    Ok(ciphertext)
  })
  let key = Bytes::make(32, 7)
  let nonce = Bytes::make(12, 8)
  let aad = Bytes::make(3, 9)
  let plaintext = Bytes::make(5, 10)
  assert_true(boolean_aead_encrypt(key, nonce, aad, plaintext) is Ok(_))
  assert_true(boolean_aead_decrypt(key, nonce, aad, plaintext) is Ok(_))
  assert_eq(encrypt_calls.val, 1)
  assert_eq(decrypt_calls.val, 1)
  clear_aead_encrypt_provider()
  clear_aead_decrypt_provider()
  assert_true(boolean_aead_encrypt(key, nonce, aad, plaintext) is Err(_))
}
