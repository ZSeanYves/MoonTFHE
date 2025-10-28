// TLWE: b = a * s + e + m  （都在环 T[X]/(X^n + 1) 内）

/// Bool 向多项式常数项编码（±0.25），其余为 0
pub fn tlwe_encode_bit_const(n : Int, b : Bool) -> Array[Int] {
  let mu = @torus.t32_encode_bit_pm(b, @torus.T32_QUARTER)
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
pub fn tlwe_encrypt(
  key : TlweKey,
  m : Array[Int],
  sigma : Float,
  rng : @rng.CsPrng,
) -> TlweCiphertext {
  let n = key.params.n
  // 安全：m 长度必须匹配参数
  if m.length() != n {
    panic()
  }

  // a(X) ← U(T^n)
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a[i] = @rng.next_u32(rng)
  }

  // e(X) ← 近似离散高斯
  let e = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    e[i] = @math.sample_discrete_gaussian_0sigma(rng, sigma)
  }
  // b = a*s + e + m
  let s_poly = tlwe_key_to_poly(key)
  let s = @math.poly_mul_negacyclic(a, s_poly)
  let be = @math.poly_add(s, e)
  let b = @math.poly_add(be, m)
  let t = { params: key.params, a, b }
  t
}
