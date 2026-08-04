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
