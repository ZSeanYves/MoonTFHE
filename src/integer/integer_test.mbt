///|
test "integer radix blocks encrypt decrypt and add" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    2,
    false,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let left = client.encrypt(0x0FUL).unwrap()
  let right = client.encrypt(1UL).unwrap()
  let sum = server.add(left, right).unwrap()
  assert_eq(client.decrypt(sum).unwrap(), 0x10UL)
  let difference = server.sub(sum, right).unwrap()
  assert_eq(client.decrypt(difference).unwrap(), 0x0FUL)
}

///|
test "integer radix bitwise operations" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    2,
    false,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let left = client.encrypt(0x36UL).unwrap()
  let right = client.encrypt(0x13UL).unwrap()
  assert_eq(
    client.decrypt(server.bitand(left, right).unwrap()).unwrap(),
    0x12UL,
  )
  assert_eq(client.decrypt(server.bitor(left, right).unwrap()).unwrap(), 0x37UL)
  assert_eq(
    client.decrypt(server.bitxor(left, right).unwrap()).unwrap(),
    0x25UL,
  )
  assert_eq(client.decrypt(server.bitnot(right).unwrap()).unwrap(), 0xECUL)
}

///|
test "integer rejects values wider than configured radix" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    1,
    false,
  ).unwrap()
  let (client, _) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  assert_true(client.encrypt(16UL) is Err(InvalidValue))
}

///|
test "integer scalar addition propagates carries and wraps" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    2,
    false,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let value = client.encrypt(0x0FUL).unwrap()
  assert_eq(
    client.decrypt(server.scalar_add(value, 1UL).unwrap()).unwrap(),
    0x10UL,
  )
  let max = client.encrypt(0xFFUL).unwrap()
  assert_eq(client.decrypt(server.scalar_add(max, 1UL).unwrap()).unwrap(), 0UL)
}

///|
test "integer comparison selection and extrema" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    1,
    false,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let three = client.encrypt(3UL).unwrap()
  let nine = client.encrypt(9UL).unwrap()
  assert_true(
    client.decrypt_bool(server.less_than(three, nine).unwrap()).unwrap(),
  )
  assert_true(
    client.decrypt_bool(server.less_or_equal(three, nine).unwrap()).unwrap(),
  )
  assert_true(
    client.decrypt_bool(server.greater_than(nine, three).unwrap()).unwrap(),
  )
  assert_true(
    client.decrypt_bool(server.greater_or_equal(nine, three).unwrap()).unwrap(),
  )
  assert_false(client.decrypt_bool(server.equal(three, nine).unwrap()).unwrap())
  assert_true(client.decrypt_bool(server.equal(three, three).unwrap()).unwrap())
  let condition = server.less_than(three, nine).unwrap()
  assert_eq(
    client.decrypt(server.select(condition, three, nine).unwrap()).unwrap(),
    3UL,
  )
  assert_eq(client.decrypt(server.min(three, nine).unwrap()).unwrap(), 3UL)
  assert_eq(client.decrypt(server.max(three, nine).unwrap()).unwrap(), 9UL)
}

///|
test "integer shifts rotations and modular multiplication" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    1,
    false,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let nine = client.encrypt(9UL).unwrap()
  assert_eq(client.decrypt(server.shift_left(nine, 1).unwrap()).unwrap(), 2UL)
  assert_eq(client.decrypt(server.shift_right(nine, 1).unwrap()).unwrap(), 4UL)
  assert_eq(client.decrypt(server.rotate_left(nine, 1).unwrap()).unwrap(), 3UL)
  assert_eq(
    client.decrypt(server.rotate_right(nine, 1).unwrap()).unwrap(),
    12UL,
  )
  let six = client.encrypt(6UL).unwrap()
  let three = client.encrypt(3UL).unwrap()
  assert_eq(client.decrypt(server.mul(six, three).unwrap()).unwrap(), 2UL)
  assert_eq(client.decrypt(server.scalar_mul(six, 3UL).unwrap()).unwrap(), 2UL)
}

///|
test "integer unsigned division and encrypted zero policy" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    1,
    false,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let thirteen = client.encrypt(13UL).unwrap()
  let three = client.encrypt(3UL).unwrap()
  let (quotient, remainder) = server.div_rem(thirteen, three).unwrap()
  assert_eq(client.decrypt(quotient).unwrap(), 4UL)
  assert_eq(client.decrypt(remainder).unwrap(), 1UL)
  let zero = client.encrypt(0UL).unwrap()
  let (zero_quotient, original_remainder) = server
    .div_rem(thirteen, zero)
    .unwrap()
  assert_eq(client.decrypt(zero_quotient).unwrap(), 0UL)
  assert_eq(client.decrypt(original_remainder).unwrap(), 13UL)
}

///|
test "integer signed comparison and arithmetic shift" {
  let parameters = integer_parameters(
    @boolean.boolean_test_parameters(),
    1,
    true,
  ).unwrap()
  let (client, server) = generate_test_keys(parameters, 0x494E5445474552UL).unwrap()
  let minus_one = client.encrypt(15UL).unwrap()
  let one = client.encrypt(1UL).unwrap()
  assert_true(
    client.decrypt_bool(server.less_than(minus_one, one).unwrap()).unwrap(),
  )
  assert_eq(
    client
    .decrypt(server.shift_right(client.encrypt(8UL).unwrap(), 1).unwrap())
    .unwrap(),
    12UL,
  )
  assert_true(server.div_rem(minus_one, one) is Err(SignedOperationUnsupported))
}
