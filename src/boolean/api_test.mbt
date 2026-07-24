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

///|
test "stable Boolean facade: serialization checksum rejects tampering" {
  let parameters = boolean_test_parameters()
  let (client, _server) = generate_test_keys(parameters, 0x43484B).unwrap()
  let encoded = client.encrypt(true).serialize()
  let tampered = encoded.to_array()
  tampered[25] = tampered[25] ^ 1U.to_byte()
  assert_true(
    client.deserialize(Bytes::from_array(tampered)) is Err(ChecksumMismatch),
  )
}

///|
test "stable Boolean facade: deterministic random NAND property circuit" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x50524F50).unwrap()
  let rng = @src.test_rng_new(0x43495243554954)
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
test "stable Boolean facade: generic LUT is explicit until PBS tables land" {
  let parameters = boolean_test_parameters()
  let (client, server) = generate_test_keys(parameters, 0x4C5554).unwrap()
  let result = server.apply_lut(client.encrypt(true), [false, true])
  assert_true(result is Err(UnsupportedLut))
}
