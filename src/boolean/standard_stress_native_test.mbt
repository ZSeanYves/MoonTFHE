///|
fn run_standard_random_circuit(
  parameters : BooleanParameters,
  seed : UInt64,
  steps : Int,
) -> Unit raise {
  let (client, server) = generate_keys(parameters).unwrap()
  let rng = @random.test_rng_new(seed)
  let mut expected = true
  let mut current = client.encrypt(expected)
  for _ in 0..<steps {
    let input = (rng.next_u32() & 1U) == 1U
    let input_ciphertext = client.encrypt(input)
    let operation = (rng.next_u32() % 6U).reinterpret_as_int()
    if operation == 0 {
      current = server.nand(current, input_ciphertext).unwrap()
      expected = !(expected && input)
    } else if operation == 1 {
      current = server.and_gate(current, input_ciphertext).unwrap()
      expected = expected && input
    } else if operation == 2 {
      current = server.or_gate(current, input_ciphertext).unwrap()
      expected = expected || input
    } else if operation == 3 {
      current = server.xor_gate(current, input_ciphertext).unwrap()
      expected = expected != input
    } else if operation == 4 {
      current = server.xnor_gate(current, input_ciphertext).unwrap()
      expected = expected == input
    } else {
      let selector = (rng.next_u32() & 1U) == 1U
      current = server
        .mux(client.encrypt(selector), current, input_ciphertext)
        .unwrap()
      expected = if selector { expected } else { input }
    }
    assert_eq(client.decrypt(current), Ok(expected))
  }
}

///|
#skip("nightly production circuit evidence")
test "standard 110: 1000 random Boolean circuit steps" {
  run_standard_random_circuit(
    boolean_110_parameters(),
    0x3131305F43495243UL,
    1000,
  )
}

///|
#skip("nightly production circuit evidence")
test "standard 128: 1000 random Boolean circuit steps" {
  run_standard_random_circuit(
    boolean_128_parameters(),
    0x3132385F43495243UL,
    1000,
  )
}
