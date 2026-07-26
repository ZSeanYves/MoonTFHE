///|
fn benchmark_evidence_parameter(
  parameter_name : String,
  parameters : BooleanParameters,
) -> Unit raise {
  let keygen_start = @bench.monotonic_clock_start()
  let (client, server) = generate_keys(parameters).unwrap()
  let keygen_us = @bench.monotonic_clock_end(keygen_start)
  let left = client.encrypt(true)
  let right = client.encrypt(true)
  // A non-trivial LUT is required here: the identity table may be optimized
  // as a ciphertext copy and would not measure programmable bootstrapping.
  let not_lut = [true, false]
  let iterations = 10
  let pbs_start = @bench.monotonic_clock_start()
  let mut pbs_output = left
  for _ in 0..<iterations {
    pbs_output = server.apply_lut(pbs_output, not_lut).unwrap()
  }
  let pbs_us = @bench.monotonic_clock_end(pbs_start) / iterations.to_double()
  let nand_start = @bench.monotonic_clock_start()
  let mut nand_output = left
  for _ in 0..<iterations {
    nand_output = server.nand(left, right).unwrap()
  }
  let nand_us = @bench.monotonic_clock_end(nand_start) / iterations.to_double()
  assert_eq(client.decrypt(pbs_output), Ok(true))
  assert_eq(client.decrypt(nand_output), Ok(false))
  let server_key_bytes = server.serialize().unwrap().length()
  let ciphertext_bytes = left.serialize().length()
  println(
    "{\"schema_version\":1,\"implementation\":\"moontfhe\",\"parameter\":\"\{parameter_name}\",\"iterations\":\{iterations},\"keygen_us\":\{keygen_us},\"pbs_us\":\{pbs_us},\"nand_us\":\{nand_us},\"server_key_bytes\":\{server_key_bytes},\"ciphertext_bytes\":\{ciphertext_bytes}}",
  )
}

///|
#skip("nightly production benchmark evidence")
test "benchmark evidence boolean-110" {
  benchmark_evidence_parameter("boolean-110", boolean_110_parameters())
}

///|
#skip("nightly production benchmark evidence")
test "benchmark evidence boolean-128" {
  benchmark_evidence_parameter("boolean-128", boolean_128_parameters())
}
