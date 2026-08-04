///|
fn measure_ciphertext_operation(
  operation : () -> Ciphertext,
  warmup : Int,
  iterations : Int,
) -> (Double, Ciphertext) {
  let mut output = operation()
  for _ in 0..<warmup {
    output = operation()
  }
  let start = @bench.monotonic_clock_start()
  for _ in 0..<iterations {
    output = operation()
  }
  (@bench.monotonic_clock_end(start) / iterations.to_double(), output)
}

///|
fn benchmark_performance_batch(
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
  let warmup = 100
  let iterations = 100
  let (pbs_us, pbs_output) = measure_ciphertext_operation(
    fn() {
      {
        inner: server.inner.programmable_bootstrap(left.inner, pbs_lut).unwrap(),
        key_id: server.key_id,
        parameters: server.parameters,
      }
    },
    warmup,
    iterations,
  )
  let (nand_us, nand_output) = measure_ciphertext_operation(
    fn() { server.nand(left, right).unwrap() },
    warmup,
    iterations,
  )
  let (and_us, and_output) = measure_ciphertext_operation(
    fn() { server.and_gate(left, right).unwrap() },
    warmup,
    iterations,
  )
  let (or_us, or_output) = measure_ciphertext_operation(
    fn() { server.or_gate(left, right).unwrap() },
    warmup,
    iterations,
  )
  let (xor_us, xor_output) = measure_ciphertext_operation(
    fn() { server.xor_gate(left, right).unwrap() },
    warmup,
    iterations,
  )
  let (xnor_us, xnor_output) = measure_ciphertext_operation(
    fn() { server.xnor_gate(left, right).unwrap() },
    warmup,
    iterations,
  )
  let (mux_us, mux_output) = measure_ciphertext_operation(
    fn() { server.mux(left, right, pbs_output).unwrap() },
    warmup,
    iterations,
  )
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
  // This LUT intentionally maps the encrypted true phase to the false output.
  assert_eq(client.decrypt(pbs_output), Ok(false))
  assert_eq(client.decrypt(nand_output), Ok(false))
  assert_eq(client.decrypt(and_output), Ok(true))
  assert_eq(client.decrypt(or_output), Ok(true))
  assert_eq(client.decrypt(xor_output), Ok(false))
  assert_eq(client.decrypt(xnor_output), Ok(true))
  assert_eq(client.decrypt(mux_output), Ok(true))
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
  let memory = server.inner.native_memory_metrics().unwrap()
  println(
    "{\"schema_version\":3,\"kind\":\"performance\",\"implementation\":\"moontfhe\",\"parameter\":\"\{parameter_name}\",\"warmup\":\{warmup},\"iterations\":\{iterations},\"keygen_us\":\{keygen_us},\"pbs_us\":\{pbs_us},\"nand_us\":\{nand_us},\"stage_metrics\":{\"key_generation_us\":\{keygen_us},\"pbs_with_ks_us\":\{pbs_us},\"pbs_without_ks_us\":\{pbs_without_ks_us},\"ksk_generation_us\":\{keygen_stages.ksk_generation_us},\"ksk_apply_us\":\{ksk_apply_us},\"bsk_coefficient_generation_us\":\{keygen_stages.bsk_coefficient_generation_us},\"bsk_fourier_conversion_us\":\{keygen_stages.bsk_fourier_conversion_us},\"polynomial_multiplication_us\":\{polynomial_multiplication_us},\"external_product_us\":\{external_product_us},\"external_product_count\":\{external_product_count},\"blind_rotation_us\":\{blind_rotation_us},\"sample_extraction_us\":\{sample_extraction_us},\"nand_us\":\{nand_us},\"and_us\":\{and_us},\"or_us\":\{or_us},\"xor_us\":\{xor_us},\"xnor_us\":\{xnor_us},\"mux_us\":\{mux_us}},\"gate_pbs_counts\":{\"nand\":1,\"and\":1,\"or\":1,\"xor\":1,\"xnor\":1,\"mux\":2},\"tracked_memory\":{\"resident_bytes\":\{memory.tracked_resident_bytes()},\"coefficient_bsk_bytes\":\{memory.coefficient_bsk_bytes()},\"fourier_bsk_bytes\":\{memory.fourier_bsk_bytes()},\"ksk_bytes\":\{memory.ksk_bytes()},\"workspace_bytes\":\{memory.workspace_bytes()}}}",
  )
}

///|
fn benchmark_allocation_evidence(
  parameter_name : String,
  parameters : BooleanParameters,
) -> Unit {
  let (client, server) = generate_keys(parameters).unwrap()
  let input = client.encrypt(true)
  let lut = @pbs.boolean_lut(
    @torus.Torus32::from_int(0x2000_0000),
    @torus.Torus32::from_int(-0x2000_0000),
  )
  let iterations = 1000
  let allocations = server.inner
    .native_kernel_allocation_count(input.inner, lut, iterations)
    .unwrap()
  let memory = server.inner.native_memory_metrics().unwrap()
  println(
    "{\"schema_version\":3,\"kind\":\"allocation\",\"implementation\":\"moontfhe\",\"parameter\":\"\{parameter_name}\",\"iterations\":\{iterations},\"native_kernel_heap_allocations\":\{allocations},\"tracked_memory\":{\"resident_bytes\":\{memory.tracked_resident_bytes()},\"coefficient_bsk_bytes\":\{memory.coefficient_bsk_bytes()},\"fourier_bsk_bytes\":\{memory.fourier_bsk_bytes()},\"ksk_bytes\":\{memory.ksk_bytes()},\"workspace_bytes\":\{memory.workspace_bytes()}}}",
  )
}

///|
fn benchmark_serialized_size(
  parameter_name : String,
  parameters : BooleanParameters,
) -> Unit {
  let (client, server) = generate_keys(parameters).unwrap()
  let ciphertext = client.encrypt(true)
  let server_key_bytes = server.serialize().unwrap().length()
  let ciphertext_bytes = ciphertext.serialize().length()
  println(
    "{\"schema_version\":3,\"kind\":\"serialized-size\",\"implementation\":\"moontfhe\",\"parameter\":\"\{parameter_name}\",\"server_key_bytes\":\{server_key_bytes},\"ciphertext_bytes\":\{ciphertext_bytes}}",
  )
}

///|
#skip("nightly production benchmark evidence")
test "benchmark performance boolean-110" {
  benchmark_performance_batch("boolean-110", boolean_110_parameters())
}

///|
#skip("nightly production benchmark evidence")
test "benchmark performance boolean-128" {
  benchmark_performance_batch("boolean-128", boolean_128_parameters())
}

///|
#skip("nightly production benchmark evidence")
test "benchmark allocation boolean-110" {
  benchmark_allocation_evidence("boolean-110", boolean_110_parameters())
}

///|
#skip("nightly production benchmark evidence")
test "benchmark allocation boolean-128" {
  benchmark_allocation_evidence("boolean-128", boolean_128_parameters())
}

///|
#skip("nightly production benchmark evidence")
test "benchmark serialized size boolean-110" {
  benchmark_serialized_size("boolean-110", boolean_110_parameters())
}

///|
#skip("nightly production benchmark evidence")
test "benchmark serialized size boolean-128" {
  benchmark_serialized_size("boolean-128", boolean_128_parameters())
}
