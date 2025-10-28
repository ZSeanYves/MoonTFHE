// TLWE 基本类型与密钥生成（只写不依赖多项式自卷积的部分）

/// TLWE 参数（最小化先用 n；后续可扩充 k、q 等）
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

/// 生成 TLWE 秘钥（s_i ∈ {0,1}）
pub fn tlwe_key_new(n : Int, rng : @rng.CsPrng) -> TlweKey {
  let params = { n, }
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (@rng.next_u64(rng) & 1) == 1
  }
  let a = { params, s }
  a
}
