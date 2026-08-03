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
test "stable Boolean facade: production keygen rejects test parameters" {
  let result = generate_keys(boolean_test_parameters())
  assert_true(result is Err(InvalidParameters))
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

///|
test "stable Boolean facade: serialization checksum rejects tampering" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x43484B).unwrap()
  let encoded = client.encrypt(true).serialize()
  let tampered = encoded.to_array()
  tampered[70] = tampered[70] ^ 1U.to_byte()
  assert_true(
    client.deserialize(Bytes::from_array(tampered)) is Err(ChecksumMismatch),
  )
}

///|
test "stable Boolean facade: v2 CRC32C and secret export boundary" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x43524332).unwrap()
  let encoded = client.encrypt(false).serialize()
  assert_eq(encoded[0], b'M')
  assert_eq(encoded[4], b'\x02')
  let short_key = serialization_key_from_bytes(Bytes::make(31, 0))
  assert_true(short_key is Err(InvalidLength))
  let key = serialization_key_from_bytes(Bytes::make(32, 0))
  let export_result = client.export_secret(key.unwrap())
  match export_result {
    Ok(blob) => {
      assert_true(blob.length() > 34)
      assert_eq(blob[0], b'M')
      assert_eq(blob[3], b'K')
    }
    Err(UnsupportedBackend) => assert_true(true)
    Err(_) => assert_true(false)
  }
}

///|
test "stable Boolean facade: server key roundtrip restores evaluation material" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x534B4559).unwrap()
  let encoded = server.serialize().unwrap()
  assert_eq(encoded[0], b'M')
  assert_eq(encoded[1], b'B')
  assert_eq(encoded[2], b'K')
  assert_eq(encoded[3], b'S')
  assert_true(encoded.length() > 90)
  let restored = ServerKey::deserialize(encoded).unwrap()
  let result = restored
    .nand(client.encrypt(true), client.encrypt(true))
    .unwrap()
  assert_eq(client.decrypt(result), Ok(false))
}

///|
test "stable Boolean facade: malformed server key is rejected before import" {
  let parameters = boolean_test_parameters()
  let (_client, server) = generate_test_keys(parameters, 0x4D424B53).unwrap()
  let encoded = server.serialize().unwrap()
  assert_true(
    ServerKey::deserialize(encoded[:89].to_owned()) is Err(InvalidLength),
  )
  let bad_crc = encoded.to_array()
  bad_crc[90] = bad_crc[90] ^ b'\x01'
  assert_true(
    ServerKey::deserialize(Bytes::from_array(bad_crc)) is Err(ChecksumMismatch),
  )
  let bad_shape = encoded.to_array()
  bad_shape[74] = bad_shape[74] + b'\x01'
  assert_true(
    ServerKey::deserialize(Bytes::from_array(bad_shape))
    is Err(InvalidServerKey),
  )
  let cross_parameter = encoded.to_array()
  cross_parameter[6] = 110U.to_byte()
  assert_true(
    ServerKey::deserialize(Bytes::from_array(cross_parameter))
    is Err(ParameterMismatch),
  )
}

///|
test "stable Boolean facade: deterministic random NAND property circuit" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x50524F50).unwrap()
  let rng = @random.test_rng_new(0x43495243554954)
  for _ in 0..<32 {
    let left = (rng.next_u32() & 1U) == 1U
    let right = (rng.next_u32() & 1U) == 1U
    let result = server
      .nand(client.encrypt(left), client.encrypt(right))
      .unwrap()
    assert_eq(client.decrypt(result).unwrap(), !(left && right))
  }
}

///|
test "stable Boolean facade: complete Boolean gate truth tables" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x47415445).unwrap()
  for left in [false, true] {
    for right in [false, true] {
      let left_ct = client.encrypt(left)
      let right_ct = client.encrypt(right)
      assert_eq(
        client.decrypt(server.and_gate(left_ct, right_ct).unwrap()).unwrap(),
        left && right,
      )
      assert_eq(
        client.decrypt(server.or_gate(left_ct, right_ct).unwrap()).unwrap(),
        left || right,
      )
      assert_eq(
        client.decrypt(server.xor_gate(left_ct, right_ct).unwrap()).unwrap(),
        left != right,
      )
      assert_eq(
        client.decrypt(server.xnor_gate(left_ct, right_ct).unwrap()).unwrap(),
        left == right,
      )
      for selector in [false, true] {
        let selected = server
          .mux(client.encrypt(selector), left_ct, right_ct)
          .unwrap()
        assert_eq(
          client.decrypt(selected).unwrap(),
          if selector {
            left
          } else {
            right
          },
        )
      }
    }
  }
}

///|
test "stable Boolean facade: all two-point LUTs are evaluated" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x4C5554).unwrap()
  for input in [false, true] {
    for table in [[false, false], [false, true], [true, false], [true, true]] {
      let result = server.apply_lut(client.encrypt(input), table).unwrap()
      assert_eq(
        client.decrypt(result),
        Ok(if input { table[1] } else { table[0] }),
      )
    }
  }
  assert_true(
    server.apply_lut(client.encrypt(true), [true]) is Err(InvalidLutLength),
  )
}

///|
test "stable Boolean facade: linear LUT paths reject a foreign key" {
  let parameters = boolean_test_parameters()
  let (_client, server) = generate_test_keys(parameters, 0x4C55544B455931UL).unwrap()
  let (foreign, _foreign_server) = generate_test_keys(
    parameters, 0x4C55544B455932UL,
  ).unwrap()
  for table in [[false, false], [false, true], [true, false], [true, true]] {
    assert_true(
      server.apply_lut(foreign.encrypt(true), table) is Err(KeyMismatch),
    )
  }
}
