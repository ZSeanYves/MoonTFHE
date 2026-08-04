///|
/// This corpus is deliberately skipped on PRs. The evidence workflow runs it
/// with --include-skipped to exercise malformed-input handling at scale.
#skip("nightly serialization mutation corpus")
test "serialization mutation corpus rejects 100000 malformed envelopes" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x4D55544154494F4EUL).unwrap()
  let ciphertext = client.encrypt(true).serialize()
  let server_key = server.serialize().unwrap()
  let serialization_key = serialization_key_from_bytes(Bytes::make(32, 0xA5)).unwrap()
  let secret = client.export_secret(serialization_key).unwrap()
  let mut rejected = 0

  for index in 0..<33334 {
    let bytes = ciphertext.to_array()
    let offset = index % bytes.length()
    bytes[offset] = bytes[offset] ^ (index.to_byte() | 1U.to_byte())
    assert_true(client.deserialize(Bytes::from_array(bytes)) is Err(_))
    rejected = rejected + 1
  }
  for index in 0..<33333 {
    let bytes = server_key.to_array()
    let offset = index % bytes.length()
    bytes[offset] = bytes[offset] ^ (index.to_byte() | 1U.to_byte())
    assert_true(ServerKey::deserialize(Bytes::from_array(bytes)) is Err(_))
    rejected = rejected + 1
  }
  for index in 0..<33333 {
    let bytes = secret.to_array()
    let offset = index % bytes.length()
    bytes[offset] = bytes[offset] ^ (index.to_byte() | 1U.to_byte())
    assert_true(
      ClientKey::import_secret(
        parameters,
        serialization_key,
        Bytes::from_array(bytes),
      )
      is Err(_),
    )
    rejected = rejected + 1
  }
  assert_eq(rejected, 100000)
}
