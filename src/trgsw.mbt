pub struct TrgswParams {
  base_log : Int
  level    : Int
  n        : Int         // = TRLWE n
}

// TRGSW 按分解层存多份 TRLWE（典型实现是 2*level 份）
///|
pub struct TrgswCiphertext {
  params : TrgswParams
  // 先用 level 份；后续按需要扩成 2*level 等
  data : Array[TrlweCiphertext]
}


///|
fn gadget_decompose(value : Int, base_log : Int, level : Int) -> Array[Int] {
  t32_decompose_lsb(value, base_log, level)
}




///| 生成全零密文
fn _trlwe_zero(params : TrlweParams) -> TrlweCiphertext {
  let n = params.n
  let a = Array::makei(n, fn(_) { 0 })
  let b = Array::makei(n, fn(_) { 0 })
  { params, a, b }
}

/// TRLWE × 整数（逐系数乘），保留 torus 效应
fn _trlwe_scalar_mul(ct : TrlweCiphertext, k : Int) -> TrlweCiphertext {
  let n = ct.params.n
  let a2 = Array::makei(n, fn(i) { t32_mul(ct.a[i], k) })
  let b2 = Array::makei(n, fn(i) { t32_mul(ct.b[i], k) })
  { params: ct.params, a: a2, b: b2 }
}


