// LWE 加密（布尔消息：true->0, false->0.5）


/// 计算 <a, s> over Torus（s_i ∈ {0,1}，选择性相加即可）
fn lwe_phase_from_a_s(a : Array[Int], s : Array[Bool]) -> Int {
  let n = a.length()
  let mut acc = 0
  for i in 0..<n {
    if s[i] {
      acc = acc + a[i]
    }
  }
  acc
}

///|
pub fn lwe_encrypt(
  key : LweKey,
  m : Bool,
  sigma : Float,
  rng : @rng.CsPrng,
) -> LweCiphertext {
  let n = key.s.length()
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a[i] = @rng.next_u32(rng)
  }
  let e = @math.sample_discrete_gaussian_0sigma(rng, sigma)

  // * 对称编码，留出安全边界
  let mu = @torus.t32_encode_bit_pm(m, @torus.T32_QUARTER)
  let b = lwe_phase_from_a_s(a, key.s) + mu + e
  let s = { a, b }
  s
}