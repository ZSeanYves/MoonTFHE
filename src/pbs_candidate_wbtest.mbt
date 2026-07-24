///|
test "pbs candidate: encrypted blind rotation hides the control bit" {
  let rng = csprng_new(0x50425343414E44)
  let n = 32
  let params : TfheParams = {
    n_lwe_in: 4,
    n_lwe_out: 4,
    sigma_lwe: 0.0,
    ks_base_log: 4,
    ks_level: 8,
    sigma_ks: 0.0,
    n_trlwe: n,
    sigma_trlwe: 0.0,
    bk_base_log: 4,
    bk_level: 8,
  }
  let key_lwe : LweKey = { s: [true, false, false, false] }
  let key_trlwe = trlwe_key_new(n, rng)
  let bsk = bsk_generate(params, key_lwe, key_trlwe, 4, 8, 0.0, rng)
  let accumulator : TrlweCiphertext = {
    params: { n, },
    a: Array::make(n, 0),
    b: Array::makei(n, fn(i) { if i == 0 { T32_QUARTER } else { 0 } }),
  }
  let ciphertext : LweCiphertext = { a: [T32_QUARTER, 0, 0, 0], b: T32_QUARTER }
  let result = _blind_rotate_trgsw(accumulator, ciphertext, bsk)
  assert_eq(trlwe_decrypt_to_poly(key_trlwe, result), accumulator.b)

  let encrypted_true : LweCiphertext = {
    a: [T32_QUARTER, 0, 0, 0],
    b: T32_QUARTER + T32_EIGHTH,
  }
  let identity = tfhe_id(params, bsk, encrypted_true)
  let inverted = tfhe_not(params, bsk, encrypted_true)
  assert_eq(lwe_decrypt(key_lwe, identity), true)
  assert_eq(lwe_decrypt(key_lwe, inverted), false)
  let random_true = lwe_encrypt_with_mu(key_lwe, true, T32_EIGHTH, 0.0, rng)
  assert_eq(lwe_decrypt(key_lwe, tfhe_id(params, bsk, random_true)), true)
  let random_true_2 = lwe_encrypt_with_mu(key_lwe, true, T32_EIGHTH, 0.0, rng)
  let combined_true = lwe_add(random_true, random_true_2)
  assert_eq(lwe_decrypt(key_lwe, combined_true), true)
  assert_eq(oracle_phase(key_lwe, combined_true), T32_QUARTER)
  assert_eq(lwe_decrypt(key_lwe, tfhe_id(params, bsk, combined_true)), true)
  let nand_true = tfhe_nand(params, bsk, random_true, random_true_2)
  assert_eq(oracle_phase(key_lwe, nand_true), -T32_EIGHTH)

  for left in [false, true] {
    for right in [false, true] {
      let encrypted_left = lwe_encrypt_with_mu(
        key_lwe,
        left,
        T32_EIGHTH,
        0.0,
        rng,
      )
      let encrypted_right = lwe_encrypt_with_mu(
        key_lwe,
        right,
        T32_EIGHTH,
        0.0,
        rng,
      )
      let nand = tfhe_nand(params, bsk, encrypted_left, encrypted_right)
      let actual = lwe_decrypt(key_lwe, nand)
      if actual != !(left && right) {
        fail(
          "NAND mismatch left=\{left} right=\{right} actual=\{actual} phase=\{oracle_phase(key_lwe, nand)}",
        )
      }
      assert_eq(
        lwe_decrypt(
          key_lwe,
          tfhe_and(params, bsk, encrypted_left, encrypted_right),
        ),
        left && right,
      )
      assert_eq(
        lwe_decrypt(
          key_lwe,
          tfhe_or(params, bsk, encrypted_left, encrypted_right),
        ),
        left || right,
      )
    }
  }
}
