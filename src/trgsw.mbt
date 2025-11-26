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

fn external_product(
  g : TrgswCiphertext, 
  v : TrlweCiphertext,
  digits : Array[Int],
) -> TrlweCiphertext {
  let params = v.params
  let _ = params.n
  let level = g.params.level

  // out = v (恒等项)
  let mut out = v

  // 累加 Σ digits[l] * Enc(s_i * g_l)
  for l in 0..<level {
    let d = digits[l]
    if d == 0 { continue }
    // g.data[l] 加密的是 (s_i * g_l)
    let gl_ct = g.data[l]
    let scaled = trlwe_scalar_mul(gl_ct, d)
    out = trlwe_ct_add(out, scaled)
  }
  out
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
fn trlwe_scalar_mul(ct : TrlweCiphertext, k : Int) -> TrlweCiphertext {
  let n = ct.params.n
  let a2 = Array::makei(n, fn(i) { t32_mul(ct.a[i], k) })
  let b2 = Array::makei(n, fn(i) { t32_mul(ct.b[i], k) })
  { params: ct.params, a: a2, b: b2 }
}


