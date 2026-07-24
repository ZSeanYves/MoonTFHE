///|
pub struct BskParams {
  base_log : Int
  level : Int
}

///|
pub struct BootstrappingKey {
  params : BskParams // base_log, level
  n_in : Int // LWE 输入维度
  n_trlwe : Int // TRLWE 多项式长度 n
  trgsw_params : TrgswParams // base_log, level, n
  trgsw_data : Array[TrgswCiphertext] // 长度 = n_in，每个是 TRGSW(s[i])
  key_switch : KeySwitchKey // sample extraction key -> client LWE key
}

/// 生成 BootstrappingKey：
/// 对每个 LWE 秘钥位 s[i] 生成一个 TRGSW(s[i])，存入 trgsw_data[i]
/// 生成后只保留加密的 GGSW 控制数据；输入秘密仅用于构造过程。

///|
pub fn bsk_generate(
  p : TfheParams,
  key_lwe : LweKey,
  key_trlwe : TrlweKey,
  base_log : Int,
  level : Int,
  sigma_bsk : Float,
  rng : CsPrng,
) -> BootstrappingKey {
  let bp : BskParams = { base_log, level }
  let n_in = p.n_lwe_in
  let n_tr = p.n_trlwe

  // TRGSW 参数：环维度 n_tr，base_log / level 来自调用参数
  let trgsw_params : TrgswParams = { base_log, level, n: n_tr }

  // 为每个 LWE 秘钥位 s[i] 生成 TRGSW(s[i])
  let trgsw_data : Array[TrgswCiphertext] = Array::makei(n_in, fn(i) {
    let bit = key_lwe.s[i]
    trgsw_encrypt_bool(trgsw_params, key_trlwe, bit, sigma_bsk, rng)
  })

  let extracted_key = lwe_key_from_trlwe_key(key_trlwe)
  let key_switch = ksk_generate(p, extracted_key, key_lwe, rng)

  { params: bp, n_in, n_trlwe: n_tr, trgsw_params, trgsw_data, key_switch }
}

///|
test "bsk: trgsw shape matches (n_in, level, n_trlwe)" {
  let r = csprng_new(0xB5C0CB)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n = p.n_trlwe

  // 构造 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(n, r)
  let base_log = 2
  let level = 3
  let sigma : Float = 3.0
  let bk = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)

  // BSK 顶层参数检查
  assert_eq(bk.params.base_log, base_log)
  assert_eq(bk.params.level, level)
  assert_eq(bk.n_in, n_in)
  assert_eq(bk.n_trlwe, n)
  assert_eq(bk.trgsw_params.base_log, base_log)
  assert_eq(bk.trgsw_params.level, level)
  assert_eq(bk.trgsw_params.n, n)

  // trgsw_data 长度应为 n_in
  assert_eq(bk.trgsw_data.length(), n_in)

  // 每个 TRGSW 应该有 2 * level 行，每行是 TRLWE(n)
  for i in 0..<n_in {
    let g = bk.trgsw_data[i]
    assert_eq(g.params.base_log, base_log)
    assert_eq(g.params.level, level)
    assert_eq(g.params.n, n)
    assert_eq(g.data.length(), 2 * level)
    for row in 0..<g.data.length() {
      let ct = g.data[row]
      assert_eq(ct.params.n, n)
      assert_eq(ct.a.length(), n)
      assert_eq(ct.b.length(), n)
    }
  }
}

///|
test "bsk: trgsw_data encodes lwe secret bit via external_product" {
  let r = csprng_new(0xB5C0CB42)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n = p.n_trlwe

  // 生成 key
  let s = Array::makei(n_in, fn(_) { false })
  s[0] = false
  s[1] = true
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(n, r)
  let base_log = 2
  let level = 3
  let sigma : Float = 0.0
  let bk = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)

  let message = trlwe_encode_bit_const(n, true)
  let ct_message = trlwe_encrypt(key_tr, message, sigma, r)
  let zero_out = external_product(bk.trgsw_data[0], ct_message)
  let one_out = external_product(bk.trgsw_data[1], ct_message)
  let zero_phase = trlwe_decrypt_to_poly(key_tr, zero_out)
  let one_phase = trlwe_decrypt_to_poly(key_tr, one_out)
  for coefficient in zero_phase {
    assert_eq(coefficient, 0)
  }
  assert_eq(t32_decode_sign(one_phase[0]), true)
}
