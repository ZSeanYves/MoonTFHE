///|TRLWE 参数：环多项式长度 n
pub struct TrlweParams {
  n : Int
}

///|TRLWE 秘钥：二进制多项式 s(X) ∈ {0,1}[X]/(X^n + 1)
pub struct TrlweKey {
  params : TrlweParams
  s : Array[Bool]
}

///|TRLWE 密文：(a(X), b(X))
pub struct TrlweCiphertext {
  params : TrlweParams
  a : Array[Int]
  b : Array[Int]
}


///| TRLWE 线性算子
fn _trlwe_ct_add(
  x : TrlweCiphertext,
  y : TrlweCiphertext,
) -> TrlweCiphertext {
  let n = x.params.n
  let a2 = Array::makei(n, fn(_) { 0 })
  let b2 = Array::makei(n, fn(_) { 0 })
  for i in 0..<n {
    a2[i] = x.a[i] + y.a[i]
    b2[i] = x.b[i] + y.b[i]
  }
  { params: x.params, a: a2, b: b2 }
}
///|
fn _trlwe_ct_sub(x : TrlweCiphertext, y : TrlweCiphertext) -> TrlweCiphertext {
  let n = x.params.n
  let a2 = Array::makei(n, fn(_) { 0 })
  let b2 = Array::makei(n, fn(_) { 0 })
  for i in 0..<n {
    a2[i] = x.a[i] - y.a[i]
    b2[i] = x.b[i] - y.b[i]
  }
  { params: x.params, a: a2, b: b2 }
}

///|生成 TRLWE 秘钥：系数 ∈ {0,1}
fn trlwe_key_new(n : Int, r : CsPrng) -> TrlweKey {
  let params : TrlweParams = { n, }
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    // 明确使用 u64 常量，避免类型提升差异
    s[i] = (next_u64(r) & 1) == 1
  }
  let t : TrlweKey = { params, s }
  t
}

///|将 {0,1} 系数秘钥转成整数多项式
fn trlwe_key_to_poly(key : TrlweKey) -> Array[Int] {
  let n = key.params.n
  let sp = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    if key.s[i] {
      sp[i] = 1
    }
  }
  sp
}

///|Bool 编码成常数多项式（±0.25）
fn trlwe_encode_bit_const(n : Int, bit : Bool) -> Array[Int] {
  let mu = t32_encode_bit_pm(bit, T32_QUARTER)
  let m = Array::makei(n, fn(_i) { 0 })
  m[0] = mu
  m
}

///|TRLWE 加密：m 必须是长度为 n 的多项式
fn trlwe_encrypt(
  key : TrlweKey,
  m : Array[Int],
  sigma : Float,
  r : CsPrng,
) -> TrlweCiphertext {
  let n = key.params.n
  if m.length() != n {
    panic()
  }

  // a(X) ← U(T^n)  
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a[i] = next_u32(r)
  }

  // e(X) 
  let e = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    e[i] = sample_discrete_gaussian_0sigma(r, sigma)
  }

  // b = a*s + e + m  （negacyclic 卷积）
  let s_poly = trlwe_key_to_poly(key)
  let s = poly_mul_negacyclic(a, s_poly)
  let be = poly_add(s, e)
  let b = poly_add(be, m)
  let t : TrlweCiphertext = { params: key.params, a, b }
  t
}

///|TRLWE 解密，得到整系数多项式：mu = b - a*s
fn trlwe_decrypt_to_poly(key : TrlweKey, ct : TrlweCiphertext) -> Array[Int] {
  let s_poly = trlwe_key_to_poly(key)
  let s = poly_mul_negacyclic(ct.a, s_poly)
  poly_sub(ct.b, s)
}

///|解出常数项布尔值（阈值 0.5）
fn trlwe_decrypt_bit0(key : TrlweKey, ct : TrlweCiphertext) -> Bool {
  let mu = trlwe_decrypt_to_poly(key, ct)
  t32_decode_sign(mu[0])
}

test "trlwe: encrypt/decrypt constant message" {
  let r = csprng_new(20241102)  // 也给种子加上 u64
  let n = 512
  let key = trlwe_key_new(n, r)
  let trials = 128
  let sigma : Float = 3.0
  let mut  ok = 0
  for _i in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let m = trlwe_encode_bit_const(n, bit)
    let ct = trlwe_encrypt(key, m, sigma, r)
    let dec = trlwe_decrypt_bit0(key, ct)
    if dec == bit { ok = ok + 1 }
  }
  assert_eq(ok, trials)
}
