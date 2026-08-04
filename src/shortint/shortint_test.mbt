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

///|
test "shortint comparison selection shifts and multiplication" {
  let parameters = shortint_parameters(
    @boolean.boolean_test_parameters(),
    16U,
    4U,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x53484F5254UL).unwrap()
  let six = client.encrypt(6U).unwrap()
  let three = client.encrypt(3U).unwrap()
  assert_eq(client.decrypt(server.equal(six, six).unwrap()).unwrap(), 1U)
  assert_eq(client.decrypt(server.equal(six, three).unwrap()).unwrap(), 0U)
  assert_eq(client.decrypt(server.less_than(three, six).unwrap()).unwrap(), 1U)
  assert_eq(client.decrypt(server.less_than(six, three).unwrap()).unwrap(), 0U)
  let selected = server.select(client.encrypt(1U).unwrap(), six, three).unwrap()
  assert_eq(client.decrypt(selected).unwrap(), 6U)
  let zero = client.encrypt(0U).unwrap()
  let (shifted_left, high) = server
    .shift_left_one(client.encrypt(9U).unwrap(), zero)
    .unwrap()
  assert_eq(client.decrypt(shifted_left).unwrap(), 2U)
  assert_eq(client.decrypt(high).unwrap(), 1U)
  let (shifted_right, low) = server
    .shift_right_one(client.encrypt(9U).unwrap(), zero)
    .unwrap()
  assert_eq(client.decrypt(shifted_right).unwrap(), 4U)
  assert_eq(client.decrypt(low).unwrap(), 1U)
  assert_eq(client.decrypt(server.mul(six, three).unwrap()).unwrap(), 2U)
  assert_eq(client.decrypt(server.scalar_mul(six, 2U).unwrap()).unwrap(), 12U)
  let (scalar_with_carry, carry) = server
    .scalar_add_with_carry(client.encrypt(15U).unwrap(), 1U)
    .unwrap()
  assert_eq(client.decrypt(scalar_with_carry).unwrap(), 0U)
  assert_eq(client.decrypt(carry).unwrap(), 1U)
}
