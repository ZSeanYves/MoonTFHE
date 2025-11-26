///|
pub struct BskParams {
  base_log : Int
  level : Int
}

///|
pub struct BootstrappingKey {
  params : BskParams
  n_in : Int
  n_trlwe : Int
  data : Array[TrlweCiphertext] // 扁平：level * n_in
  s_bits : Array[Bool]          // ★ Dev-only：公开的 s[i]
}


///|
fn _bsk_to_trgsw_array(bk : BootstrappingKey) -> Array[TrgswCiphertext] {
  let base_log = bk.params.base_log
  let level = bk.params.level
  let n = bk.n_trlwe
  let n_in = bk.n_in
  let params_trgsw : TrgswParams = { base_log, level, n }
  let out = Array::makei(n_in, fn(i) {
    let data = Array::makei(level, fn(l) { bk.data[bsk_idx(l, i, n_in)] })
    { params: params_trgsw, data }
  })
  out
}

///|线性下标计算：bsk.data[l * n_in + i]
fn bsk_idx(l : Int, i : Int, n_in : Int) -> Int {
  l * n_in + i
}

///|
fn phase_from_bsk_public(bk : BootstrappingKey, ct : LweCiphertext) -> Int {
  let n = bk.n_in
  let mut dot = 0
  for i in 0..<n {
    if bk.s_bits[i] {
      dot = t32_add(dot, ct.a[i])
    }
  }
  t32_sub(ct.b, dot)
}

// TODO:后续替换为 TRGSW 外积，目前仅占位
/// 构造“常数多项式” m(X) ：m[0] = mu，其余 0
fn _const_poly(n : Int, mu : Int) -> Array[Int] {
  let m = Array::makei(n, fn(_i) { 0 })
  if n > 0 {
    m[0] = mu
  }
  m
}

///|
pub fn bsk_generate(
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
  let data : Array[TrlweCiphertext] = Array::makei(cells, fn(_i) {
    let params : TrlweParams = { n, }
    let a = Array::makei(n, fn(_) { 0 })
    let b = Array::makei(n, fn(_) { 0 })
    { params, a, b }
  })
  // 每个 (l, i) 存一份 TRLWE，明文常数项约为 ±g_l
  for l in 0..<level {
    // 这一层的“权重” g_l：随着 l 增大逐层减小
    // 再整体右移 3 位：每层幅度缩小 1/8，减弱对 PBS 的扰动
  let amp_l = T32_QUARTER >> (l + 3) 
    for i in 0..<n_in {
      let bit = key_lwe.s[i]
      // bit = true  → 正数   （解密 sign 为 true）
      // bit = false → 负数   （解密 sign 为 false）
      let mu = if bit { amp_l } else { -amp_l }
      let m = _const_poly(n, mu)
      let ct = trlwe_encrypt(key_trlwe, m, sigma, rng)
      data[bsk_idx(l, i, n_in)] = ct
    }
  }

  // 开发态：公开保存 s[i]，用于无密钥 PBS
  let s_bits = {
    let arr = Array::makei(n_in, fn(_) { false })
    for i in 0..<n_in {
      arr[i] = key_lwe.s[i]
    }
    arr
  }
  { params: bp, n_in, n_trlwe: n, data, s_bits }
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
