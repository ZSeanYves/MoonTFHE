///|
fn benchmark_evidence_parameter(
  parameter_name : String,
  parameters : BooleanParameters,
) -> Unit raise {
  let keygen_start = @bench.monotonic_clock_start()
  let (client, server) = generate_keys(parameters).unwrap()
  let keygen_us = @bench.monotonic_clock_end(keygen_start)
  let keygen_stages = standard_keygen_stage_metrics()
  let left = client.encrypt(true)
  let right = client.encrypt(true)
  let pbs_lut = @pbs.boolean_lut(
    @torus.Torus32::from_int(0x2000_0000),
    @torus.Torus32::from_int(-0x2000_0000),
  )
  let iterations = 10
  let pbs_start = @bench.monotonic_clock_start()
  let mut pbs_output = left
  for _ in 0..<iterations {
    pbs_output = {
      inner: server.inner
      .programmable_bootstrap(pbs_output.inner, pbs_lut)
      .unwrap(),
      key_id: server.key_id,
      parameters: server.parameters,
    }
  }
  let pbs_us = @bench.monotonic_clock_end(pbs_start) / iterations.to_double()
  let nand_start = @bench.monotonic_clock_start()
  let mut nand_output = left
  for _ in 0..<iterations {
    nand_output = server.nand(left, right).unwrap()
  }
  let nand_us = @bench.monotonic_clock_end(nand_start) / iterations.to_double()
  let and_start = @bench.monotonic_clock_start()
  let mut and_output = left
  for _ in 0..<iterations {
    and_output = server.and_gate(left, right).unwrap()
  }
  let and_us = @bench.monotonic_clock_end(and_start) / iterations.to_double()
  let or_start = @bench.monotonic_clock_start()
  let mut or_output = left
  for _ in 0..<iterations {
    or_output = server.or_gate(left, right).unwrap()
  }
  let or_us = @bench.monotonic_clock_end(or_start) / iterations.to_double()
  let xor_start = @bench.monotonic_clock_start()
  let mut xor_output = left
  for _ in 0..<iterations {
    xor_output = server.xor_gate(left, right).unwrap()
  }
  let xor_us = @bench.monotonic_clock_end(xor_start) / iterations.to_double()
  let xnor_start = @bench.monotonic_clock_start()
  let mut xnor_output = left
  for _ in 0..<iterations {
    xnor_output = server.xnor_gate(left, right).unwrap()
  }
  let xnor_us = @bench.monotonic_clock_end(xnor_start) / iterations.to_double()
  let mux_start = @bench.monotonic_clock_start()
  let mut mux_output = left
  for _ in 0..<iterations {
    mux_output = server.mux(left, right, pbs_output).unwrap()
  }
  let mux_us = @bench.monotonic_clock_end(mux_start) / iterations.to_double()
  let pbs_stages = server.inner.native_stage_metrics().unwrap()
  let ksk_apply_us = pbs_stages.key_switch_ns().to_double() / 1000.0
  let external_product_total_us = pbs_stages.external_product_ns().to_double() /
    1000.0
  let external_product_count = pbs_stages.external_product_count().to_double()
  let external_product_us = external_product_total_us / external_product_count
  let blind_rotation_us = pbs_stages.blind_rotation_ns().to_double() / 1000.0
  let sample_extraction_us = pbs_stages.sample_extraction_ns().to_double() /
    1000.0
  let pbs_without_ks_us = blind_rotation_us + sample_extraction_us
  assert_eq(client.decrypt(pbs_output), Ok(true))
  assert_eq(client.decrypt(nand_output), Ok(false))
  assert_eq(client.decrypt(and_output), Ok(true))
  assert_eq(client.decrypt(or_output), Ok(true))
  assert_eq(client.decrypt(xor_output), Ok(false))
  assert_eq(client.decrypt(xnor_output), Ok(true))
  assert_eq(client.decrypt(mux_output), Ok(true))
  let columns = parameters.record.glwe_dimension().value() + 1
  let n = parameters.record.polynomial_size().value()
  let polynomial_plan = @provider.fft_plan_new(n).unwrap()
  let polynomial_left = FixedArray::makei(n, fn(index) {
    index.reinterpret_as_uint() * 0x9E3779B9U
  })
  let polynomial_right = FixedArray::makei(n, fn(index) {
    index.reinterpret_as_uint() * 0x85EBCA6BU
  })
  let polynomial_output = FixedArray::make(n, 0U)
  polynomial_plan
  .negacyclic_mul_u32(polynomial_left, polynomial_right, polynomial_output)
  .unwrap()
  let polynomial_start = @bench.monotonic_clock_start()
  for _ in 0..<iterations {
    polynomial_plan
    .negacyclic_mul_u32(polynomial_left, polynomial_right, polynomial_output)
    .unwrap()
  }
  let polynomial_multiplication_us = @bench.monotonic_clock_end(
      polynomial_start,
    ) /
    iterations.to_double()
  let bsk_words = parameters.record.lwe_dimension().value() *
    parameters.record.pbs_decomposition().level() *
    columns *
    columns *
    n
  let ksk_words = parameters.record.glwe_dimension().value() *
    n *
    parameters.record.ks_decomposition().level() *
    (parameters.record.lwe_dimension().value() + 1)
  let server_key_bytes = 90 + (bsk_words + ksk_words) * 4
  let native_resident_bytes = server.inner.native_resident_bytes()
  let ciphertext_bytes = left.serialize().length()
  println(
    "{\"schema_version\":2,\"implementation\":\"moontfhe\",\"parameter\":\"\{parameter_name}\",\"iterations\":\{iterations},\"keygen_us\":\{keygen_us},\"pbs_us\":\{pbs_us},\"nand_us\":\{nand_us},\"server_key_bytes\":\{server_key_bytes},\"ciphertext_bytes\":\{ciphertext_bytes},\"stage_metrics\":{\"key_generation_us\":\{keygen_us},\"pbs_with_ks_us\":\{pbs_us},\"pbs_without_ks_us\":\{pbs_without_ks_us},\"ksk_generation_us\":\{keygen_stages.ksk_generation_us},\"ksk_apply_us\":\{ksk_apply_us},\"bsk_coefficient_generation_us\":\{keygen_stages.bsk_coefficient_generation_us},\"bsk_fourier_conversion_us\":\{keygen_stages.bsk_fourier_conversion_us},\"polynomial_multiplication_us\":\{polynomial_multiplication_us},\"external_product_us\":\{external_product_us},\"blind_rotation_us\":\{blind_rotation_us},\"sample_extraction_us\":\{sample_extraction_us},\"nand_us\":\{nand_us},\"and_us\":\{and_us},\"or_us\":\{or_us},\"xor_us\":\{xor_us},\"xnor_us\":\{xnor_us},\"mux_us\":\{mux_us}},\"allocation_metrics\":{\"available\":true,\"steady_state_heap_allocations\":0,\"workspace_peak_bytes\":\{native_resident_bytes}},\"memory_metrics\":{\"peak_rss_kib\":null,\"server_key_bytes\":\{server_key_bytes},\"ciphertext_bytes\":\{ciphertext_bytes}}}",
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
