// TLWE 解密：mu(X) = b - a*s；常数项符号位即布尔值

/// 解出整多项式
pub fn tlwe_decrypt_to_poly(key : TlweKey, ct : TlweCiphertext) -> Array[Int] {
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
  let s = @math.poly_mul_negacyclic(ct.a, s_poly)
  @math.poly_sub(ct.b, s)
}

/// 按“常数项编码 ±0.25”的规则解出布尔值
pub fn tlwe_decrypt_bit0(key : TlweKey, ct : TlweCiphertext) -> Bool {
  let mu = tlwe_decrypt_to_poly(key, ct)
  @torus.t32_decode_sign(mu[0])
}
