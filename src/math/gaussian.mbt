// 离散高斯占位实现：CLT 近似法（避免使用 ln/cos），开发/测试足够。

/// 从 N(0, sigma^2) 的离散高斯采样一个整数噪声
pub fn sample_discrete_gaussian_0sigma(rng : @rng.CsPrng, sigma : Float) -> Int {
  if sigma <= 0.0 {
    return 0
  }
  // CLT 近似：z ≈ sum_{i=1..12} U(0,1) - 6 ~ N(0,1)
  let mut s = 0.0
  for _i in 0..<12 {
    s = s + @rng.next_f64_01(rng).to_double()
  }
  let z = s - 6.0
  (z * sigma.to_double()).round().to_int()
}
