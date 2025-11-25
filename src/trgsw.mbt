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

// 先做“空密文”：加密 0（占位）——方便 blind_rotate 的接口接通
///|
pub fn trgsw_encrypt_zero(
  params : TrgswParams,
  _rng : CsPrng,
) -> TrgswCiphertext {
  let n = params.n
  let dummy = Array::makei(n, fn(_) { 0 })
  let shell : TrlweCiphertext = { params: { n, }, a: dummy, b: dummy }
  let arr = Array::makei(params.level, fn(_) { shell })
  { params, data: arr }
}

///| TRGSW × TRLWE 外积实现
fn external_product(
  g : TrgswCiphertext,
  v : TrlweCiphertext,
) -> TrlweCiphertext {
  let level = g.params.level
  let base_log = g.params.base_log
  let n = g.params.n

  // Gadget decomposition of v.a and v.b
  let decomp : Array[Int] = []
  for i in 0..<n {
    let part = gadget_decompose(v.a[i], base_log, level)
    for j in 0..<level {
      decomp.push(part[j])
    }
  }
  for i in 0..<n {
    let part = gadget_decompose(v.b[i], base_log, level)
    for j in 0..<level {
      decomp.push(part[j])
    }
  }

  // 外积累加器，初始化为全零
  let mut acc = trlwe_zero(v.params)
  for i in 0..<(2 * level) {
    let scaled = trlwe_scalar_mul(g.data[i], decomp[i])
    acc = _trlwe_ct_add(acc, scaled)
  }
  acc
}

///| 将 Int 分解为 level 个 base 表示的 digit（从低位到高位）
fn gadget_decompose(value : Int, base_log : Int, level : Int) -> Array[Int] {
  let digits = Array::makei(level, fn(_) { 0 })
  let mut tmp = value >> (32 - base_log * level)
  let mask = (1 << base_log) - 1
  for i in 0..<level {
    digits[i] = tmp & mask
    tmp = tmp >> base_log
  }
  digits
}

///| 生成全零密文
fn trlwe_zero(params : TrlweParams) -> TrlweCiphertext {
  let n = params.n
  let a = Array::makei(n, fn(_) { 0 })
  let b = Array::makei(n, fn(_) { 0 })
  { params, a, b }
}

///| TRLWE × 整数（逐系数乘）
fn trlwe_scalar_mul(ct : TrlweCiphertext, k : Int) -> TrlweCiphertext {
  let n = ct.params.n
  let a2 = Array::makei(n, fn(i) { ct.a[i] * k })
  let b2 = Array::makei(n, fn(i) { ct.b[i] * k })
  { params: ct.params, a: a2, b: b2 }
}


///|
test "external_product: output dimension and stability" {
  let n = 8
  let level = 2
  let base_log = 3
  let params : TrgswParams = { base_log, level, n }
  let trlwe_params : TrlweParams = { n, }

  // 输入密文 v = 全 0
  let poly = Array::makei(n, fn(_) { 0 })
  let v : TrlweCiphertext = { params: trlwe_params, a: poly, b: poly }

  // 构造伪 TRGSW（全部密文置 1，用于测试结构）
  let dummy : TrlweCiphertext = {
    params: trlwe_params,
    a: Array::makei(n, fn(_) { 1 }),
    b: Array::makei(n, fn(_) { 1 }),
  }
  let g : TrgswCiphertext = {
    params,
    data: Array::makei(2 * level, fn(_) { dummy }),
  }
  let out = external_product(g, v)
  assert_eq(out.a.length(), n)
  assert_eq(out.b.length(), n)
}