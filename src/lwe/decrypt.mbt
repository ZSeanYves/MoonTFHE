// LWE 解密：相位减去 <a,s>，再阈值判定

/// 解密得到布尔值
pub fn lwe_decrypt(key : LweKey, ct : LweCiphertext) -> Bool {
  let n = key.s.length()
  let mut mu = ct.b
  for i in 0..<n {
    if key.s[i] {
      mu = mu - ct.a[i]
    }
  }
  // 对称解码：看符号位
  @torus.t32_decode_sign(mu)
}