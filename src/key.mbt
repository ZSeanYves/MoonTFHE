///|工具：整型幂（快速幂）
fn int_pow(base : Int, exp : Int) -> Int {
  if exp <= 0 {
    return 1
  }
  let mut b = base
  let mut e = exp
  let mut r = 1
  while e > 0 {
    if (e & 1) == 1 {
      r = r * b
    }
    b = b * b
    e = e >> 1
  }
  r
}

///|KSK 参数与结构
pub struct KskParams {
  base_log : Int
  level : Int
}

///|
pub struct KeySwitchKey {
  params : KskParams
  n_in : Int
  n_out : Int
  // 扁平存储：长度 = level * n_in
  data : Array[LweCiphertext]
}



// TOOLS
///|计算 KSK 中 (i, j) 的线性下标
fn ksk_idx(i : Int, j : Int, n_in : Int) -> Int {
  i * n_in + j
}
///|
fn ksk_params_from(p0 : TfheParams) -> KskParams {
  let a:KskParams = { base_log: p0.ks_base_log, level: p0.ks_level }
  a
}




///|
fn _ksk_generate(
  p0 : TfheParams,
  key_in : LweKey,
  key_out : LweKey,
  rng : CsPrng,
) -> KeySwitchKey {
  let kp = ksk_params_from(p0)
  let b = 1 << kp.base_log
  let n_in = p0.n_lwe_in
  let n_out = p0.n_lwe_out
  let cells = kp.level * n_in

  // 先用“零密文”占位，确保每个单元可写
  let data : Array[LweCiphertext] = Array::makei(cells, fn(_t) {
    let a = Array::makei(n_out, fn(_k) { 0 })
    { a, b: 0 }
  })
  for i in 0..<kp.level {
    let scale = int_pow(b, i)
    for j in 0..<n_in {
      let bit = key_in.s[j]
      let mu = if bit { scale } else { 0 }
      let t = lwe_encrypt_const_torus(key_out, mu, p0.sigma_ks, rng)
      let t1 = { val: t }

      // 取出单元，字段级拷贝，然后回写
      let idx = ksk_idx(i, j, n_in)
      let cell : Ref[LweCiphertext] = { val: data[idx] }
      let n = t.a.length()
      for k in 0..<n {
        cell.val.a[k] = t1.val.a[k]
      }
      cell.val.b = t1.val.b
      let cell1 = cell.val
      data[idx] = cell1
    }
  }
  let s = { params: kp, n_in, n_out, data }
  s
}


///|直接加密“torus 常数”消息：b = <a,s> + mu + e
fn lwe_encrypt_const_torus(
  key : LweKey,
  mu : Int,
  sigma : Float,
  rng : CsPrng,
) -> LweCiphertext {
  let n = key.s.length()
  let a = Array::makei(n, fn(_i) { next_u32(rng) })
  let mut acc = 0
  for i in 0..<n {
    if key.s[i] {
      acc = acc + a[i]
    }
  }
  let e = sample_discrete_gaussian_0sigma(rng, sigma)
  let s = { a, b: acc + mu + e }
  s
}

///|LSB 分解：返回 level 个以 2^{base_log} 为基的“位片”
fn decompose_torus32_lsb(x : Int, base_log : Int, level : Int) -> Array[Int] {
  let b = 1 << base_log
  let mask = b - 1
  let limbs = Array::makei(level, fn(_i) { 0 })
  let xu = x.reinterpret_as_uint()
  for i in 0..<level {
    let shift = i * base_log
    limbs[i] = ((xu >> shift) & mask.reinterpret_as_uint()).reinterpret_as_int()
  }
  limbs
}

///|线性算子（缩放/加/减）
fn lwe_ct_scale(ct : LweCiphertext, k : Int) -> LweCiphertext {
  let n = ct.a.length()
  let a2 = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a2[i] = ct.a[i] * k
  }
  let s = { a: a2, b: ct.b * k }
  s
}
///|
fn _lwe_ct_add(x : LweCiphertext, y : LweCiphertext) -> LweCiphertext {
  let n = x.a.length()
  let a2 = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a2[i] = x.a[i] + y.a[i]
  }
  let s = { a: a2, b: x.b + y.b }
  s
}
///|
fn lwe_ct_sub(x : LweCiphertext, y : LweCiphertext) -> LweCiphertext {
  let n = x.a.length()
  let a2 = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a2[i] = x.a[i] - y.a[i]
  }
  let s = { a: a2, b: x.b - y.b }
  s
}

///| 应用 KSK：ct(s_in) → ct'(s_out)
fn _ksk_apply(
  p0 : TfheParams,
  ksk : KeySwitchKey,
  ct_in : LweCiphertext,
) -> LweCiphertext {
  let n_out = p0.n_lwe_out
  let mut acc = { a: Array::makei(n_out, fn(_i) { 0 }), b: ct_in.b }
  let base_log = ksk.params.base_log
  let level = ksk.params.level
  let n_in = ksk.n_in
  for j in 0..<n_in {
    let limbs = decompose_torus32_lsb(ct_in.a[j], base_log, level)
    for i in 0..<level {
      let d = limbs[i]
      if d == 0 {
        continue
      }
      let idx = ksk_idx(i, j, n_in)
      let term = lwe_ct_scale(ksk.data[idx], d)
      acc = lwe_ct_sub(acc, term)
    }
  }
  acc
}


///| Public API: 生成 KeySwitchKey
pub fn ksk_generate(
  p0      : TfheParams,
  key_in  : LweKey,
  key_out : LweKey,
  rng     : CsPrng,
) -> KeySwitchKey {
  _ksk_generate(p0, key_in, key_out, rng)
}

///| Public API: 应用 KeySwitchKey
pub fn ksk_apply(
  p0    : TfheParams,
  ksk   : KeySwitchKey,
  ct_in : LweCiphertext,
) -> LweCiphertext {
  _ksk_apply(p0, ksk, ct_in)
}


test "ksk: lwe(n_in) -> lwe(n_out) preserves boolean message" {
  // 1. 用已有的小参数集
  let p0 = tfhe_params_small_trlwe()

  let rng = csprng_new(0xDEAD_BEEF)

  let key_in  = lwe_key_new(p0.n_lwe_in,  rng)
  let key_out = lwe_key_new(p0.n_lwe_out, rng)

  let ksk = ksk_generate(p0, key_in, key_out, rng)

  let trials = 200
  let sigma  = p0.sigma_lwe
  let mut ok = 0

  for _i in 0..<trials {
    let bit = (next_u64(rng) & 1) == 1

    let ct_in  = lwe_encrypt(key_in,  bit, sigma, rng)
    let ct_out = ksk_apply(p0, ksk, ct_in)

    let dec    = lwe_decrypt(key_out, ct_out)
    if dec == bit {
      ok = ok + 1
    }
  }

  assert_eq(ok, trials)
}
///| KSK roundtrip: LWE(32) -> LWE(64) 保持布尔消息不变
test "ksk: lwe(32) -> lwe(64) preserves boolean message" {
  // 手动构造一份专门用于 KSK 的 TfheParams
  // 注意：ks_base_log * ks_level 必须 >= 32（Torus 是 32bit）
  let p0 : TfheParams = {
    n_lwe_in: 32,
    n_lwe_out: 64,
    sigma_lwe: 3.0,
    ks_base_log: 4, // B = 16
    ks_level: 8, // 16^8 = 2^32，刚好覆盖 32bit
    sigma_ks: 3.0,

    // 下面这些字段在这个测试里不会用到，随便给合法值就行
    n_trlwe: 32,
    sigma_trlwe: 3.2,
    bk_base_log: 1,
    bk_level: 2,
  }
  let rng = csprng_new(0xCAFEBABE)
  let key_in = lwe_key_new(p0.n_lwe_in, rng)
  let key_out = lwe_key_new(p0.n_lwe_out, rng)
  let ksk = ksk_generate(p0, key_in, key_out, rng)
  let trials = 200
  let sigma = p0.sigma_lwe
  let mut ok = 0
  for _i in 0..<trials {
    let bit = (next_u64(rng) & 1) == 1
    let ct_in = lwe_encrypt(key_in, bit, sigma, rng)
    let ct_out = ksk_apply(p0, ksk, ct_in)
    let dec = lwe_decrypt(key_out, ct_out)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}
