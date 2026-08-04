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
