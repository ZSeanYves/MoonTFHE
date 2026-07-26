///|
fn measure_parameter(
  parameter_name : String,
  parameters : @boolean.BooleanParameters,
) -> Unit raise {
  let keygen_start = @bench.monotonic_clock_start()
  let (client, server) = @boolean.generate_keys(parameters).unwrap()
  let keygen_us = @bench.monotonic_clock_end(keygen_start)
  let left = client.encrypt(true)
  let right = client.encrypt(true)
  let identity = [false, true]
  let iterations = 10
  let pbs_start = @bench.monotonic_clock_start()
  let mut pbs_output = left
  for _ in 0..<iterations {
    pbs_output = server.apply_lut(pbs_output, identity).unwrap()
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
fn main raise {
  match @env.args() {
    ["boolean-110"] =>
      measure_parameter("boolean-110", @boolean.boolean_110_parameters())
    ["boolean-128"] =>
      measure_parameter("boolean-128", @boolean.boolean_128_parameters())
    [] => {
      measure_parameter("boolean-110", @boolean.boolean_110_parameters())
      measure_parameter("boolean-128", @boolean.boolean_128_parameters())
    }
    _ => fail("usage: moontfhe-benchmark [boolean-110|boolean-128]")
  }
}
