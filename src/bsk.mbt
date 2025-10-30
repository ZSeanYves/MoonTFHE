///|
pub struct BskParams {
  base_log : Int
  level : Int
}

///|
pub struct BootstrappingKey {
  params : BskParams
  n_in : Int                    // LWE 输入维度
  n_trlwe : Int                 // 环多项式长度
  data : Array[TrlweCiphertext] // 扁平长度 = level * n_in
}

// 线性下标
///|
fn bsk_idx(l : Int, i : Int, n_in : Int) -> Int {
  l * n_in + i
}


// 生成：占位实现（内容为 s[i] 的布尔常数多项式）
// TODO:后续替换为 TRGSW 外积所需的条目即可，无需改上层接口
/// 构造“常数多项式” m(X) ：m[0] = mu，其余 0
fn const_poly(n : Int, mu : Int) -> Array[Int] {
  let m = Array::makei(n, fn(_i) { 0 })
  if n > 0 {
    m[0] = mu
  }
  m
}

/// 生成 Bootstrapping Key（占位）：
/// 为每个 (level, i) 生成一条 TRLWE 密文，加密的是 s[i] 的布尔常数（±0.25）
/// base_log/level 仅存入元信息，后续接 TRGSW/外积时直接复用该结构
fn bsk_generate(
  p : TfheParams,
  key_lwe : LweKey,
  key_trlwe : TrlweKey,
  base_log : Int,
  level : Int,
  sigma : Float,
  rng : CsPrng,
) -> BootstrappingKey {
  let bp : BskParams = { base_log, level }
  let n_in = p.n_lwe_in
  let n = p.n_trlwe
  let cells = level * n_in
  let data : Array[TrlweCiphertext] = Array::makei(cells, fn(_) {
    let params : TrlweParams = { n, }
    // 预置空壳，保证可写
    let a = Array::makei(n, fn(_) { 0 })
    let b = Array::makei(n, fn(_) { 0 })
    { params, a, b }
  })
  for l in 0..<level {
    for i in 0..<n_in {
      let bit = key_lwe.s[i]
      let mu = if bit {
        T32_QUARTER
      } else {
        t32_add(T32_HALF, T32_QUARTER) // = 0.75
      }
      let m = const_poly(n, mu)
      let ct = trlwe_encrypt(key_trlwe, m, sigma, rng)
      data[bsk_idx(l, i, n_in)] = ct
    }
  }
  { params: bp, n_in, n_trlwe: n, data }
}



///|
test "bsk: shape is level * n_in, and each ct matches TRLWE n" {
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
  assert_eq(bk.params.base_log, base_log)
  assert_eq(bk.params.level, level)
  assert_eq(bk.n_in, n_in)
  assert_eq(bk.n_trlwe, n)
  assert_eq(bk.data.length(), level * n_in)

  // 每条密文尺寸应为 n
  for idx in 0..<bk.data.length() {
    assert_eq(bk.data[idx].a.length(), n)
    assert_eq(bk.data[idx].b.length(), n)
    assert_eq(bk.data[idx].params.n, n)
  }
}

///|
test "bsk: content decrypts to s[i] at each level (bit on const term)" {
  let r = csprng_new(0xA11CE)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n = p.n_trlwe

  // 随机 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(n, r)
  let base_log = 1
  let level = 2
  let sigma : Float = 3.0
  let bk = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)

  // 随机抽查若干 (l, i)
  let checks = if n_in < 8 { n_in } else { 8 }
  let mut ok = 0
  for i in 0..<checks {
    for l in 0..<level {
      let ct = bk.data[bsk_idx(l, i, n_in)]
      let bit_dec = trlwe_decrypt_bit0(key_tr, ct)
      if bit_dec == key_lwe.s[i] {
        ok = ok + 1
      }
    }
  }
  assert_eq(ok, checks * level)
}
