/// 生成长度为 n 的零多项式
pub fn poly_zero(n : Int) -> Array[Int] {
  Array::makei(n, fn(_i) { 0 })
}


/// 拷贝
pub fn poly_clone(a : Array[Int]) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i]
  }
  out
}

/// 长度
pub fn poly_len(a : Array[Int]) -> Int {
  a.length()
}

/// 逐项相等性检查（用于测试/断言）
pub fn poly_eq(a : Array[Int], b : Array[Int]) -> Bool {
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
pub fn poly_add(a : Array[Int], b : Array[Int]) -> Array[Int] {
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
pub fn poly_sub(a : Array[Int], b : Array[Int]) -> Array[Int] {
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
pub fn poly_neg(a : Array[Int]) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = -a[i]
  }
  out
}

/// 逐项加常数
pub fn poly_scalar_add(a : Array[Int], c : Int) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i] + c
  }
  out
}

/// 逐项乘常数
pub fn poly_scalar_mul(a : Array[Int], c : Int) -> Array[Int] {
  let n = a.length()
  let out = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    out[i] = a[i] * c
  }
  out
}





/// 将任意长度的系数折回到长度 n（X^n ≡ -1）
pub fn poly_from_coeffs_fold(coeffs : Array[Int], n : Int) -> Array[Int] {
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
pub fn poly_mul_negacyclic(a : Array[Int], b : Array[Int]) -> Array[Int] {
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
pub fn poly_rotate_negacyclic(a : Array[Int], k : Int) -> Array[Int] {
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
