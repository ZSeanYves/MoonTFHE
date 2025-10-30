/// 生成长度为 n 的零多项式
fn _poly_zero(n : Int) -> Array[Int] {
  Array::makei(n, fn(_i) { 0 })
}


/// 拷贝
fn poly_clone(a : Array[Int]) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i]
  }
  out
}

/// 长度
fn _poly_len(a : Array[Int]) -> Int {
  a.length()
}

/// 逐项相等性检查（用于测试/断言）
fn poly_eq(a : Array[Int], b : Array[Int]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

/// 逐项加法
fn poly_add(a : Array[Int], b : Array[Int]) -> Array[Int] {
  let n = a.length()
  // 可选：若不等长，panic 更早暴露错误
  if b.length() != n {
    panic()
  }
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i] + b[i]
  }
  out
}

/// 逐项减法
fn poly_sub(a : Array[Int], b : Array[Int]) -> Array[Int] {
  let n = a.length()
  if b.length() != n {
    panic()
  }
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i] - b[i]
  }
  out
}

/// 逐项取负
fn _poly_neg(a : Array[Int]) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = -a[i]
  }
  out
}

/// 逐项加常数
fn _poly_scalar_add(a : Array[Int], c : Int) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i] + c
  }
  out
}

/// 逐项乘常数
fn _poly_scalar_mul(a : Array[Int], c : Int) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i] * c
  }
  out
}





/// 将任意长度的系数折回到长度 n（X^n ≡ -1）
fn poly_from_coeffs_fold(coeffs : Array[Int], n : Int) -> Array[Int] {
  let out = Array::makei(n, fn(_i) { 0 })
  let m = coeffs.length()
  for i in 0..<m {
    let c = coeffs[i]
    if c == 0 { continue }
    let r = i % n
    let q = i / n
    if (q % 2) == 0 { out[r] = out[r] + c } else { out[r] = out[r] - c }
  }
  out
}

/// 负循环卷积：c = a * b mod (X^n + 1)
fn poly_mul_negacyclic(a : Array[Int], b : Array[Int]) -> Array[Int] {
  let n = a.length()
  let c = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    let ai = a[i]
    if ai == 0 { continue }
    for j in 0..<n {
      let prod = ai * b[j]
      let idx = i + j
      if idx < n { c[idx] = c[idx] + prod } else {
        let t = idx - n
        c[t] = c[t] - prod   // X^{n+t} ≡ -X^t
      }
    }
  }
  c
}

/// 旋转：a * X^k mod (X^n + 1)
fn poly_rotate_negacyclic(a : Array[Int], k : Int) -> Array[Int] {
  let n = a.length()
  if n == 0 { return a }
  let kk = ((k % n) + n) % n
  if kk == 0 { return poly_clone(a) }
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    let coeff = a[i]
    if coeff == 0 { continue }
    let dest = i + kk
    if dest < n { out[dest] = out[dest] + coeff } else {
      out[dest - n] = out[dest - n] - coeff  // 折返取反
    }
  }
  out
}

// TODO:后续可将CLT 替换为CDT 离散高斯采样器
/// 从 N(0, sigma^2) 的离散高斯采样一个整数噪声
fn sample_discrete_gaussian_0sigma(rng : CsPrng, sigma : Float) -> Int {
  if sigma <= 0.0 {
    return 0
  }
  // CLT 近似：z ≈ sum_{i=1..12} U(0,1) - 6 ~ N(0,1)
  let mut s = 0.0
  for _i in 0..<12 {
    s = s + next_f64_01(rng).to_double()
  }
  let z = s - 6.0
  (z * sigma.to_double()).round().to_int()
}



// 占位版 NTT 接口
//TODO：v0.2 做性能优化时再填充真实实现。
/// 计划对象占位（将来可换成包含根表、bit-reverse 索引等的结构体）
/// 预生成 NTT 计划（占位：直接返回 Unit）
fn _ntt_plan_new(_n : Int) -> Unit {
  ()
}

/// 原地 NTT 变换（占位：不对输入做任何修改）
fn _ntt_inplace(_plan : Unit, _a : Array[Int]) -> Unit {
  // TODO: implement NTT in v0.2
}

/// 原地逆 NTT 变换（占位：不对输入做任何修改）
fn _intt_inplace(_plan : Unit, _a : Array[Int]) -> Unit {
  // TODO: implement inverse NTT in v0.2
}




// 小工具
///|
fn abs_f(x : Float) -> Float {
  if x >= 0.0 {
    x
  } else {
    -x
  }
}
///|
fn min_f(a : Float, b : Float) -> Float {
  if a < b {
    a
  } else {
    b
  }
}
///|
fn max_f(a : Float, b : Float) -> Float {
  if a > b {
    a
  } else {
    b
  }
}

///|
test "rng: reproducible sequences (same seed => same numbers)" {
  let r1 : CsPrng = csprng_new(123456789)
  let r2 : CsPrng = csprng_new(123456789)
  for _i in 0..<50 {
    let a = next_u32(r1)
    let b = next_u32(r2)
    assert_eq(a, b)
  }
}

///|
test "rng: different seeds likely diverge" {
  let r1 : CsPrng = csprng_new(1)
  let r2 : CsPrng = csprng_new(2)
  let mut same = 0
  for _i in 0..<20 {
    if next_u32(r1) == next_u32(r2) {
      same = same + 1
    }
  }
  // 极小概率才会一直相等
  assert_eq(same < 3, true)
}

///|
test "rng: next_f64_01 in [0,1) and mean ~ 0.5" {
  let r : CsPrng = csprng_new(42)
  let n = 20000
  let mut sum = 0.0
  let mut lo = 1.0
  let mut hi = 0.0
  for _i in 0..<n {
    let u = next_f64_01(r)
    assert_eq(u >= 0.0, true)
    assert_eq(u < 1.0, true)
    sum = sum + u.to_double()
    lo = min_f(lo.to_float(), u).to_double()
    hi = max_f(hi.to_float(), u).to_double()
  }
  let mean = sum / n.to_double()
  // 均值接近 0.5（宽松容差）
  assert_eq(abs_f(mean.to_float() - 0.5) < 0.03, true)
  // 覆盖范围应较宽
  assert_eq(lo < 0.02, true)
  assert_eq(hi > 0.98, true)
}

///|
test "gaussian: mean ~ 0, variance ~ sigma^2 (coarse bounds)" {
  let r : CsPrng = csprng_new(987654321)
  let sigma = 3.0
  let n = 20000
  let mut sum = 0.0
  let mut sumsq = 0.0
  for _i in 0..<n {
    let g = sample_discrete_gaussian_0sigma(r, sigma.to_float()).to_float()
    sum = sum + g.to_double()
    sumsq = sumsq + (g * g).to_double()
  }
  let mean = sum / n.to_double()
  let var_hat = sumsq / n.to_double() - mean * mean

  // 均值接近 0
  assert_eq(abs_f(mean.to_float()) < 0.2, true)

  // 方差大致落在 [0.5*sigma^2, 1.5*sigma^2] 内（CLT 近似+离散化，放宽区间）
  let target = sigma * sigma
  assert_eq(var_hat > 0.5 * target, true)
  assert_eq(var_hat < 1.5 * target, true)
}


///|
test "poly: fold coeffs modulo X^n+1" {
  let n = 8
  // X^9 + 2X^8 + 3X^7 + 4X^1 + 5
  let coeffs = [5, 4, 0, 0, 0, 0, 0, 3, 2, 1]
  let f = poly_from_coeffs_fold(coeffs, n)
  // X^8 ≡ -1, X^9 ≡ -X
  // => (-1)*2 + (-X)*1 + 3X^7 + 4X + 5
  // 常数项: 5 - 2 = 3; X: 4 - 1 = 3; X^7: 3
  assert_eq(poly_eq(f, [3, 3, 0, 0, 0, 0, 0, 3]), true)
}

///|
test "poly: negacyclic mul — monomials" {
  let _n = 8
  // X^3 * X^6 = X^9 ≡ -X
  let a = [0, 0, 0, 1, 0, 0, 0, 0]
  let b = [0, 0, 0, 0, 0, 0, 1, 0]
  let c = poly_mul_negacyclic(a, b)
  // -X
  assert_eq(poly_eq(c, [0, -1, 0, 0, 0, 0, 0, 0]), true)
}

///|
test "poly: rotate negacyclic" {
  let _n = 8
  // a = 1 + 2X + 3X^7
  let a = [1, 2, 0, 0, 0, 0, 0, 3]
  // 乘 X^2： 1→X^2, 2X→2X^3, 3X^7→3X^9≡-3X
  let r = poly_rotate_negacyclic(a, 2)
  assert_eq(poly_eq(r, [0, -3, 1, 2, 0, 0, 0, 0]), true)
}