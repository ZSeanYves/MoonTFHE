///|
test "stable Boolean facade: native SecretExport uses fresh AES-GCM nonces" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x4E4154495645).unwrap()
  let key = serialization_key_from_bytes(Bytes::make(32, 0xA5)).unwrap()
  let first = client.export_secret(key).unwrap()
  let second = client.export_secret(key).unwrap()
  assert_eq(first.length(), 104)
  assert_eq(second.length(), 104)
  assert_eq(first[0], b'M')
  assert_eq(first[1], b'T')
  assert_eq(first[2], b'S')
  assert_eq(first[3], b'K')
  assert_eq(first[4], b'\x02')
  assert_eq(first[5], b'\x02')
  assert_true(first[66:78].to_owned() != second[66:78].to_owned())
  assert_true(first != second)
}

///|
test "stable Boolean facade: native rejects legacy MTSK before authentication" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x4C45474D54534BUL).unwrap()
  let key = serialization_key_from_bytes(Bytes::make(32, 0x51)).unwrap()
  let legacy = client.export_secret(key).unwrap().to_array()
  legacy[4] = b'\x01'
  assert_true(
    ClientKey::import_secret(parameters, key, Bytes::from_array(legacy))
    is Err(UnsupportedVersion),
  )
}

///|
test "stable Boolean facade: native SecretExport import authenticates key" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x494D504F5254).unwrap()
  let ciphertext = client.encrypt(true)
  let key = serialization_key_from_bytes(Bytes::make(32, 0x3C)).unwrap()
  let exported = client.export_secret(key).unwrap()
  let imported = ClientKey::import_secret(parameters, key, exported).unwrap()
  assert_eq(imported.decrypt(ciphertext), Ok(true))
  let wrong_key = serialization_key_from_bytes(Bytes::make(32, 0xC3)).unwrap()
  assert_true(
    ClientKey::import_secret(parameters, wrong_key, exported)
    is Err(AuthenticationFailed),
  )
  let wrong_tag = exported.to_array()
  let last = wrong_tag.length() - 1
  wrong_tag[last] = wrong_tag[last] ^ b'\x01'
  assert_true(
    ClientKey::import_secret(parameters, key, Bytes::from_array(wrong_tag))
    is Err(AuthenticationFailed),
  )
  assert_true(
    ClientKey::import_secret(boolean_110_parameters(), key, exported)
    is Err(ParameterMismatch),
  )
}

///|
test "stable Boolean facade: native 110-bit keygen closes encrypt and NAND" {
  let parameters = boolean_110_parameters()
  let (client, server) = generate_keys(parameters).unwrap()
  assert_eq(client.decrypt(client.encrypt(false)), Ok(false))
  assert_eq(client.decrypt(client.encrypt(true)), Ok(true))
  let result = server.nand(client.encrypt(true), client.encrypt(true)).unwrap()
  assert_eq(client.decrypt(result), Ok(false))
}

///|
test "stable Boolean facade: native 128-bit path reuses standard PBS" {
  let parameters = boolean_128_parameters()
  let (client, server) = generate_keys(parameters).unwrap()
  assert_eq(client.decrypt(client.encrypt(false)), Ok(false))
  assert_eq(client.decrypt(client.encrypt(true)), Ok(true))
  let result = server.nand(client.encrypt(true), client.encrypt(false)).unwrap()
  assert_eq(client.decrypt(result), Ok(true))
}

///|
test "stable Boolean facade: native 110-bit MBKS import rebuilds Fourier PBS" {
  let parameters = boolean_110_parameters()
  let (client, server) = generate_keys(parameters).unwrap()
  let restored = ServerKey::deserialize(server.serialize().unwrap()).unwrap()
  let result = restored
    .nand(client.encrypt(true), client.encrypt(false))
    .unwrap()
  assert_eq(client.decrypt(result), Ok(true))
}

///|
test "stable Boolean facade: native 128-bit MBKS import rebuilds Fourier PBS" {
  let parameters = boolean_128_parameters()
  let (client, server) = generate_keys(parameters).unwrap()
  let restored = ServerKey::deserialize(server.serialize().unwrap()).unwrap()
  let result = restored
    .nand(client.encrypt(true), client.encrypt(true))
    .unwrap()
  assert_eq(client.decrypt(result), Ok(false))
}
