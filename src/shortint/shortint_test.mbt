///|
test "shortint reference blocks encrypt decrypt and add" {
  let parameters = shortint_parameters(
    @boolean.boolean_test_parameters(),
    4U,
    4U,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x53484F5254UL).unwrap()
  let left = client.encrypt(1U).unwrap()
  let right = client.encrypt(2U).unwrap()
  let sum = server.unchecked_add(left, right).unwrap()
  assert_eq(client.decrypt(sum).unwrap(), 3U)
  assert_eq(sum.degree().value(), 3U)
  assert_eq(sum.noise_level().value(), 3U)
  let difference = server.unchecked_sub(sum, right).unwrap()
  assert_eq(client.decrypt(difference).unwrap(), 1U)
  let scalar_sum = server.scalar_add(left, 2U).unwrap()
  assert_eq(client.decrypt(scalar_sum).unwrap(), 3U)
}

///|
test "shortint bitwise operations reuse Boolean blocks" {
  let parameters = shortint_parameters(
    @boolean.boolean_test_parameters(),
    8U,
    4U,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x53484F5254UL).unwrap()
  let left = client.encrypt(6U).unwrap()
  let right = client.encrypt(3U).unwrap()
  assert_eq(client.decrypt(server.bitand(left, right).unwrap()).unwrap(), 2U)
  assert_eq(client.decrypt(server.bitor(left, right).unwrap()).unwrap(), 7U)
  assert_eq(client.decrypt(server.bitxor(left, right).unwrap()).unwrap(), 5U)
}

///|
test "shortint message modulus rejects out of range values" {
  let parameters = shortint_parameters(
    @boolean.boolean_test_parameters(),
    8U,
    4U,
  ).unwrap()
  let (client, _) = generate_test_keys(parameters, 0x53484F5254UL).unwrap()
  assert_true(client.encrypt(8U) is Err(InvalidMessage))
}

///|
test "shortint parameters reject non power of two modulus" {
  assert_true(
    shortint_parameters(@boolean.boolean_test_parameters(), 3U, 4U)
    is Err(InvalidModulus),
  )
}
