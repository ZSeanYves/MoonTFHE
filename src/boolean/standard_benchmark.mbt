///|
/// Native-only standard PBS benchmark. Key generation is deliberately outside
/// the timed closure; the benchmark measures steady-state NAND throughput.
test "bench standard Boolean NAND 110" (bench : @bench.T) {
  let (client, server) = generate_keys(boolean_110_parameters()).unwrap()
  let left = client.encrypt(true)
  let right = client.encrypt(false)
  bench.bench(fn() { bench.keep(server.nand(left, right).unwrap()) })
}

///|
test "bench standard Boolean NAND 128" (bench : @bench.T) {
  let (client, server) = generate_keys(boolean_128_parameters()).unwrap()
  let left = client.encrypt(true)
  let right = client.encrypt(false)
  bench.bench(fn() { bench.keep(server.nand(left, right).unwrap()) })
}

///|
test "bench standard programmable bootstrap 110" (bench : @bench.T) {
  let (client, server) = generate_keys(boolean_110_parameters()).unwrap()
  let input = client.encrypt(true)
  let identity = [false, true]
  bench.bench(fn() { bench.keep(server.apply_lut(input, identity).unwrap()) })
}

///|
test "bench standard programmable bootstrap 128" (bench : @bench.T) {
  let (client, server) = generate_keys(boolean_128_parameters()).unwrap()
  let input = client.encrypt(true)
  let identity = [false, true]
  bench.bench(fn() { bench.keep(server.apply_lut(input, identity).unwrap()) })
}
