/// TLWE 参数
/// TODO:目前先用 n；后续可扩充 k、q 等
pub struct TlweParams {
  n : Int
}

/// TLWE 秘钥：s(X) ∈ {0,1}^n（环上二进制多项式）
pub struct TlweKey {
  params : TlweParams
  s : Array[Bool]
}

/// TLWE 密文：(a(X), b(X)) ∈ T[X]/(X^n+1)
pub struct TlweCiphertext {
  params : TlweParams
  a : Array[Int]
  b : Array[Int]
}
///TLWE 线性算子
fn lwe_add(x : LweCiphertext, y : LweCiphertext) -> LweCiphertext {
  let n = x.a.length()
  let a = Array::makei(n, fn(i){ t32_add(x.a[i], y.a[i]) })
  let b = t32_add(x.b, y.b)
  { a, b }
}
///|
fn _lwe_sub(x : LweCiphertext, y : LweCiphertext) -> LweCiphertext {
  let n = x.a.length()
  let a = Array::makei(n, fn(i) { t32_sub(x.a[i], y.a[i]) })
  let b = t32_sub(x.b, y.b)
  { a, b }
}
///|
fn _lwe_add_plain(x : LweCiphertext, c : Int) -> LweCiphertext {
  { a: x.a, b: t32_add(x.b, c) }
}
///|
fn lwe_sub_plain(x : LweCiphertext, c : Int) -> LweCiphertext {
  { a: x.a, b: t32_sub(x.b, c) }
}

/// 生成 TLWE 秘钥（s_i ∈ {0,1}）
fn tlwe_key_new(n : Int, rng : CsPrng) -> TlweKey {
  let params:TlweParams = { n, }
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (next_u64(rng) & 1) == 1
  }
  let a:TlweKey = { params, s }
  a
}

// TLWE: b = a * s + e + m  （都在环 T[X]/(X^n + 1) 内）
/// Bool 向多项式常数项编码（±0.25），其余为 0
fn tlwe_encode_bit_const(n : Int, b : Bool) -> Array[Int] {
  let mu = t32_encode_bit_pm(b, T32_QUARTER)
  let m = Array::makei(n, fn(_i) { 0 })
  m[0] = mu
  m
}

/// 将 {0,1}^n 的密钥向量转成环上多项式 s(X)
fn tlwe_key_to_poly(key : TlweKey) -> Array[Int] {
  let n = key.params.n
  let sp = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    if key.s[i] {
      sp[i] = 1
    } // 1 ∈ Torus32
  }
  sp
}

/// TLWE 加密：输入消息多项式 m（长度必须为 n）
fn tlwe_encrypt(
  key : TlweKey,
  m : Array[Int],
  sigma : Float,
  rng : CsPrng,
) -> TlweCiphertext {
  let n = key.params.n
  // 安全：m 长度必须匹配参数
  if m.length() != n {
    panic()
  }

  // a(X) ← U(T^n)
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a[i] = next_u32(rng)
  }

  // e(X) ← 近似离散高斯
  let e = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    e[i] = sample_discrete_gaussian_0sigma(rng, sigma)
  }
  // b = a*s + e + m
  let s_poly = tlwe_key_to_poly(key)
  let s = poly_mul_negacyclic(a, s_poly)
  let be = poly_add(s, e)
  let b = poly_add(be, m)
  let t:TlweCiphertext = { params: key.params, a, b }
  t
}

// TLWE 解密：mu(X) = b - a*s；常数项符号位即布尔值
/// 解出整多项式
fn tlwe_decrypt_to_poly(key : TlweKey, ct : TlweCiphertext) -> Array[Int] {
  let n = key.params.n
  // mu = b - a*s
  let s_poly = {
    let sp = Array::makei(n, fn(_i) { 0 })
    for i in 0..<n {
      if key.s[i] {
        sp[i] = 1
      }
    }
    sp
  }
  let s = poly_mul_negacyclic(ct.a, s_poly)
  poly_sub(ct.b, s)
}

/// 按“常数项编码 ±0.25”的规则解出布尔值
fn tlwe_decrypt_bit0(key : TlweKey, ct : TlweCiphertext) -> Bool {
  let mu = tlwe_decrypt_to_poly(key, ct)
  t32_decode_sign(mu[0])
}

/// 把 TLWE 相位（torus 32 位）映射到环 Z[X]/(X^n+1) 的“旋转步数”k：
fn torus_phase_to_rot_k(t : Int, n : Int) -> Int {
  let l = log2_pow2(n)
  let shift = 32 - l
  // 以无符号视角右移，得到 [0, n) 的整步
  let ku = (t.reinterpret_as_uint() >> shift) & (n.reinterpret_as_uint() - 1)
  ku.reinterpret_as_int()
}

/// 计算 TLWE 相位 phi = b - <a, s>  
fn _tlwe_phase(a : Array[Int], b : Int, s : Array[Bool]) -> Int {
  let n = a.length()
  let mut acc = 0
  for i in 0..<n {
    if s[i] {
      acc = acc + a[i]
    }
  }
  b - acc
}
///|
test "tlwe: encrypt/decrypt roundtrip (n=512, 200 trials)" {
  let rng = csprng_new(20241028)
  let n = 512
  let key = tlwe_key_new(n, rng)
  let trials = 200
  let sigma = 3.0 // 小噪声，远小于 ±0.25 的安全边界
  let mut ok = 0
  for _i in 0..<trials {
    let bit = (next_u64(rng) & 1) == 1
    let m = tlwe_encode_bit_const(n, bit)
    let ct = tlwe_encrypt(key, m, sigma.to_float(), rng)
    let dec = tlwe_decrypt_bit0(key, ct)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}