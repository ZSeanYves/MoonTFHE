/// TODO:伪·NAND：仅占位，真实 NAND 需要二元 LUT 。
fn _hom_nand_single_input_todo(
  _p : TfheParams,
  x : LweCiphertext,
) -> LweCiphertext {
  x
}

/// DEBUG: 列出 XNOR gate 在四种输入下的解密结果（零噪声）
test "debug gate: XNOR truth table (oracle PBS, zero-noise)" {
  // 测试专用零噪声参数
  let p : TfheParams = {
    n_lwe_in: 256,
    n_lwe_out: 256,
    sigma_lwe: 0.0,
    ks_base_log: 4,
    ks_level: 8,
    sigma_ks: 0.0,
    n_trlwe: 512,
    sigma_trlwe: 0.0,
    bk_base_log: 3,
    bk_level: 8,
  }
  let rng = csprng_new(0xDEAD_BEEF)
  let key_lwe = lwe_key_new(p.n_lwe_in, rng)
  let key_trlwe = trlwe_key_new(p.n_trlwe, rng)
  let bk = bsk_generate(
    p,
    key_lwe,
    key_trlwe,
    p.bk_base_log,
    p.bk_level,
    0.0, // BSK 也关噪声
    rng,
  )
  let sigma = p.sigma_lwe
  let inputs : Array[(Bool, Bool)] = [
    (false, false),
    (false, true),
    (true, false),
    (true, true),
  ]
  for idx in 0..<inputs.length() {
    let (a, b) = inputs[idx]
    let ca = lwe_encrypt(key_lwe, a, sigma, rng)
    let cb = lwe_encrypt(key_lwe, b, sigma, rng)
    let cout = tfhe_xnor(p, bk, ca, cb)
    let _dec = lwe_decrypt(key_lwe, cout)
    ////println("XNOR debug: a= \{a}, b=\{b},  => dec=\{_dec}")
  }
}

/// XNOR(x,y) 在随机输入上的真值测试（零噪声参数）
test "gate: XNOR(x,y) truth over random bits (oracle PBS, zero-noise)" {
  let p : TfheParams = {
    n_lwe_in: 256,
    n_lwe_out: 256,
    sigma_lwe: 0.0,
    ks_base_log: 4,
    ks_level: 8,
    sigma_ks: 0.0,
    n_trlwe: 512,
    sigma_trlwe: 0.0,
    bk_base_log: 3,
    bk_level: 8,
  }
  let rng = csprng_new(0x1234_5678)
  let key_lwe = lwe_key_new(p.n_lwe_in, rng)
  let key_trlwe = trlwe_key_new(p.n_trlwe, rng)
  let bk = bsk_generate(
    p,
    key_lwe,
    key_trlwe,
    p.bk_base_log,
    p.bk_level,
    0.0,
    rng,
  )
  let sigma = p.sigma_lwe
  let trials = 128
  let mut ok = 0
  for _i in 0..<trials {
    let a = (next_u64(rng) & 1) == 1
    let b = (next_u64(rng) & 1) == 1
    let ca = lwe_encrypt(key_lwe, a, sigma, rng)
    let cb = lwe_encrypt(key_lwe, b, sigma, rng)
    let cout = tfhe_xnor(p, bk, ca, cb)
    let dec = lwe_decrypt(key_lwe, cout)
    let expect = a == b
    if dec == expect {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}
