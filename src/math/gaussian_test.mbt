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
  let r1 : @rng.CsPrng = @rng.csprng_new(123456789)
  let r2 : @rng.CsPrng = @rng.csprng_new(123456789)
  for _i in 0..<50 {
    let a = @rng.next_u32(r1)
    let b = @rng.next_u32(r2)
    assert_eq(a, b)
  }
}

///|
test "rng: different seeds likely diverge" {
  let r1 : @rng.CsPrng = @rng.csprng_new(1)
  let r2 : @rng.CsPrng = @rng.csprng_new(2)
  let mut same = 0
  for _i in 0..<20 {
    if @rng.next_u32(r1) == @rng.next_u32(r2) {
      same = same + 1
    }
  }
  // 极小概率才会一直相等
  assert_eq(same < 3, true)
}

///|
test "rng: next_f64_01 in [0,1) and mean ~ 0.5" {
  let r : @rng.CsPrng = @rng.csprng_new(42)
  let n = 20000
  let mut sum = 0.0
  let mut lo = 1.0
  let mut hi = 0.0
  for _i in 0..<n {
    let u = @rng.next_f64_01(r)
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
  let r : @rng.CsPrng = @rng.csprng_new(987654321)
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
