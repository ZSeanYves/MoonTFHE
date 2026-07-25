///|
test "stable Boolean facade: native SecretExport uses fresh AES-GCM nonces" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x4E4154495645).unwrap()
  let key = serialization_key_from_bytes(Bytes::make(32, 0xA5)).unwrap()
  let first = client.export_secret(key).unwrap()
  let second = client.export_secret(key).unwrap()
  assert_eq(first.length(), 60)
  assert_eq(second.length(), 60)
  assert_eq(first[0], b'M')
  assert_eq(first[1], b'T')
  assert_eq(first[2], b'S')
  assert_eq(first[3], b'K')
  assert_true(first[22:34].to_owned() != second[22:34].to_owned())
  assert_true(first != second)
}
