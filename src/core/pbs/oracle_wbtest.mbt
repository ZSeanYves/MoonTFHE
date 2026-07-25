///|
fn make_toy_oracle(
  order : PbsOrder,
) -> (@lwe.LweSecretKey, @lwe.LweSecretKey, BootstrapKey) {
  let small_dimension = @params.lwe_dimension(1).unwrap()
  let small_key = @lwe.lwe_key_from_binary_secret(small_dimension, [true]).unwrap()
  let glwe_parameters = @glwe.glwe_parameters(1, 8).unwrap()
  let glwe_key = @glwe.glwe_keygen(
    glwe_parameters,
    @random.test_rng_new(0x4F5241434C45474C),
  )
  let big_key = glwe_key.to_extracted_lwe_key().unwrap()
  let decomposition = @params.decomposition_parameters(4, 8).unwrap()
  let zero_noise = @random.test_zero_noise_fixture()
  let key_switch = @keyswitch.keyswitch_keygen(
    big_key,
    small_key,
    decomposition,
    zero_noise,
    @random.test_rng_new(0x4F5241434C454B53),
  ).unwrap()
  let ggsw_parameters = @ggsw.ggsw_parameters(glwe_parameters, 4, 8).unwrap()
  let control = @ggsw.ggsw_encrypt_boolean(
    ggsw_parameters,
    glwe_key,
    true,
    zero_noise,
    @random.test_rng_new(0x4F5241434C454253),
  ).unwrap()
  let bootstrap_key = bootstrap_key_from_encrypted_parts(
    small_dimension,
    glwe_parameters,
    [control],
    key_switch,
    order,
  ).unwrap()
  (small_key, big_key, bootstrap_key)
}

///|
test "pbs oracle: both PBS orders preserve their external key domains" {
  let amplitude = @torus.Torus32::from_int(0x2000_0000)
  let identity = boolean_lut(amplitude.neg(), amplitude)
  for order in [BootstrapKeyswitch, KeyswitchBootstrap] {
    let (small_key, big_key, bootstrap_key) = make_toy_oracle(order)
    for message in [false, true] {
      let input_key = if order is BootstrapKeyswitch {
        small_key
      } else {
        big_key
      }
      let output_key = if order is BootstrapKeyswitch {
        small_key
      } else {
        big_key
      }
      let input = input_key
        .lwe_encrypt_binary(
          message,
          @random.test_zero_noise_fixture(),
          @random.test_rng_new(
            0x4F5241434C45494E ^ (if message { 1UL } else { 0UL }),
          ),
        )
        .unwrap()
      let output = bootstrap_key
        .programmable_bootstrap(input, identity)
        .unwrap()
      assert_eq(output.parameters(), output_key.parameters())
      assert_eq(output_key.lwe_decrypt_binary(output), Ok(message))
    }
  }
}

///|
test "pbs oracle: 10000 deterministic toy circuit steps preserve semantics" {
  let (small_key, _big_key, bootstrap_key) = make_toy_oracle(BootstrapKeyswitch)
  let amplitude = @torus.Torus32::from_int(0x2000_0000)
  let identity = boolean_lut(amplitude.neg(), amplitude)
  let negation = boolean_lut(amplitude, amplitude.neg())
  let circuit_rng = @random.test_rng_new(0x3130303030434952)
  let mut expected = true
  let mut ciphertext = small_key
    .lwe_encrypt_binary(
      expected,
      @random.test_zero_noise_fixture(),
      @random.test_rng_new(0x3130303030494E50),
    )
    .unwrap()
  for _ in 0..<10000 {
    if (circuit_rng.next_u32() & 1U) == 0U {
      ciphertext = bootstrap_key
        .programmable_bootstrap(ciphertext, identity)
        .unwrap()
    } else {
      ciphertext = bootstrap_key
        .programmable_bootstrap(ciphertext, negation)
        .unwrap()
      expected = !expected
    }
    assert_eq(small_key.lwe_decrypt_binary(ciphertext), Ok(expected))
  }
}
