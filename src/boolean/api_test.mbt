///|
test "stable Boolean facade: test keygen and NAND" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x424F4F4C).unwrap()
  let left = client.encrypt(true)
  let right = client.encrypt(false)
  let result = server.nand(left, right).unwrap()
  assert_eq(client.decrypt(result).unwrap(), true)
}

///|
test "stable Boolean facade: production keygen refuses incomplete backend" {
  let result = generate_keys(boolean_128_parameters())
  assert_true(result is Err(UnsupportedBackend))
}

///|
test "stable Boolean facade: serialization round trip" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x534552).unwrap()
  let ciphertext = client.encrypt(true)
  let restored = client.deserialize(ciphertext.serialize()).unwrap()
  let result = server.not(restored).unwrap()
  assert_eq(client.decrypt(result).unwrap(), false)
}
