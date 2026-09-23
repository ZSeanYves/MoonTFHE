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

///|
test "stable Boolean facade: direct OR encoding matches the four-point oracle" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x4449524543544F52).unwrap()
  for left in [false, true] {
    for right in [false, true] {
      let left_ciphertext = client.encrypt(left)
      let right_ciphertext = client.encrypt(right)
      let direct = server
        .binary_or_encoded(
          left_ciphertext,
          right_ciphertext,
          boolean_amplitude(),
        )
        .unwrap()
      assert_eq(client.decrypt(direct), Ok(left || right))
      assert_eq(
        client.decrypt(
          server.or_gate(left_ciphertext, right_ciphertext).unwrap(),
        ),
        Ok(left || right),
      )
    }
  }
}
