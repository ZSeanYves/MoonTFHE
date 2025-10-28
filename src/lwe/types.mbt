// LWE 基本类型定义与密钥生成

/// LWE 秘钥：s ∈ {0,1}^n
pub struct LweKey {
  s : Array[Bool]
}

/// LWE 密文：a ∈ T^n, b ∈ T
pub struct LweCiphertext {
  a : Array[Int]
  b : Int
}

/// 生成长度为 n 的 {0,1} 秘钥
pub fn lwe_key_new(n : Int, rng : @rng.CsPrng) -> LweKey {
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    // 低位随机成 {0,1}
    s[i] = (@rng.next_u64(rng) & 1) == 1
  }
  let a = { s, }
  a
}
