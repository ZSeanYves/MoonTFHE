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
