///|
test "stable Boolean facade: evaluation rejects a same-key cross-parameter object" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x504152414D444F4D).unwrap()
  let encrypted = client.encrypt(true)
  let forged : Ciphertext = {
    inner: encrypted.inner,
    key_id: encrypted.key_id,
    parameters: boolean_110_parameters(),
  }
  assert_true(server.not(forged) is Err(KeyMismatch))
  assert_true(client.decrypt(forged) is Err(KeyMismatch))
}
