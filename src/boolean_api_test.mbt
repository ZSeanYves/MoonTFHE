///|
test "boolean facade: external NAND workflow and serialization" {
  let (client, server) = experimental_boolean_keygen(0x50464F)
  for left in [false, true] {
    for right in [false, true] {
      let left_ct = client.encrypt(left)
      let right_ct = client.encrypt(right)
      let restored = client.deserialize_ciphertext(left_ct.serialize()).unwrap()
      let result = server.nand(restored, right_ct).unwrap()
      assert_eq(client.decrypt(result).unwrap(), !(left && right))
    }
  }
}

///|
test "boolean facade: rejects ciphertext from another key" {
  let (client_a, server_a) = experimental_boolean_keygen(0xA)
  let (client_b, _server_b) = experimental_boolean_keygen(0xB)
  let foreign = client_b.encrypt(true)
  assert_true(server_a.not(foreign) is Err(KeyMismatch))
  assert_true(
    client_a.deserialize_ciphertext(foreign.serialize()) is Err(KeyMismatch),
  )
}
