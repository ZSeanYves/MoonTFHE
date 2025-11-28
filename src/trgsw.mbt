// ===================== TRGSW 参数与结构 =====================
pub struct TrgswParams {
  base_log : Int   // log_B，B = 2^base_log
  level    : Int   // ℓ
  n        : Int   // = TRLWE n (环维度 N)
}

///|
pub struct TrgswCiphertext {
  params : TrgswParams
  data   : Array[TrlweCiphertext]  // length = 2 * params.level
}

// ===================== gadget 分解 =====================
///|
fn gadget_decompose(value : Int, base_log : Int, level : Int) -> Array[Int] {
  t32_decompose_lsb_trgsw(value, base_log, level)
}


/// 对一个多项式 poly 做 gadget 分解：
//// 返回长度为 level 的数组，每个元素是一整个“digit 多项式”
/// 第 j 个 digit 多项式的第 i 项 = gadget_decompose(poly[i])[j]
///|
fn _gadget_decompose_poly(
  poly     : Array[Int],
  base_log : Int,
  level    : Int,
) -> Array[Array[Int]] {
  let n = poly.length()
  let res = Array::makei(level, fn(_) {
    Array::makei(n, fn(_) { 0 })
  })

  for i in 0..<n {
    let digits = gadget_decompose(poly[i], base_log, level)
    for j in 0..<level {
      res[j][i] = digits[j]
    }
  }

  res
}

// ===================== TRLWE 辅助运算 =====================
/// 生成全零 TRLWE 密文（a=0, b=0）
///|
fn _trlwe_zero(params : TrlweParams) -> TrlweCiphertext {
  let n = params.n
  let a = Array::makei(n, fn(_) { 0 })
  let b = Array::makei(n, fn(_) { 0 })
  { params, a, b }
}

/// TRLWE × 整数（逐系数乘），保留 torus 效应
///|
fn _trlwe_scalar_mul(ct : TrlweCiphertext, k : Int) -> TrlweCiphertext {
  let n = ct.params.n
  let a2 = Array::makei(n, fn(i) { t32_mul(ct.a[i], k) })
  let b2 = Array::makei(n, fn(i) { t32_mul(ct.b[i], k) })
  { params: ct.params, a: a2, b: b2 }
}

///|
fn _trlwe_mul_by_plain_poly(
  ct : TrlweCiphertext,
  poly_plain : Array[Int],
) -> TrlweCiphertext {
  let n = ct.params.n
  let params = ct.params
  let mut acc = _trlwe_zero(params)
  for k in 0..<n {
    let c = poly_plain[k]
    if c == 0 {
      continue
    }

    // 对 a, b 多项式分别做 X^k 的 negacyclic 旋转
    let a_rot = poly_rotate_negacyclic(ct.a, k)
    let b_rot = poly_rotate_negacyclic(ct.b, k)

    let a_scaled = Array::makei(n, fn(i) { t32_mul_k(a_rot[i], c) })
    let b_scaled = Array::makei(n, fn(i) { t32_mul_k(b_rot[i], c) })
    let tmp : TrlweCiphertext = { params, a: a_scaled, b: b_scaled }
    acc = trlwe_ct_add(acc, tmp)
  }
  acc
}

// ===================== Torus 整数分解（MBS-first） =====================
///|
fn t32_decompose_lsb_trgsw(x : Int, base_log : Int, level : Int) -> Array[Int] {
  let b = 1 << base_log
  let mask = b - 1
  let limbs = Array::makei(level, fn(_) { 0 })

  // 提取高位 bits（MSB-first 风格）
  let ux = x.reinterpret_as_uint() >> (32 - base_log * level)
  for i in 0..<level {
    let shift = base_log * (level - 1 - i)
    let ui = (ux >> shift) & mask.reinterpret_as_uint()
    limbs[i] = ui.reinterpret_as_int()
  }
  limbs
}


// ===================== TRGSW × TRLWE 外积（GSW 真语义） =====================
fn external_product(
  g : TrgswCiphertext,
  v : TrlweCiphertext,
) -> TrlweCiphertext {
  let level = g.params.level
  let base_log = g.params.base_log
  let n = g.params.n

  // 1) 对 a(X), b(X) 都做 gadget 分解
  let digit_a = _gadget_decompose_poly(v.a, base_log, level) // [level][n]
  let digit_b = _gadget_decompose_poly(v.b, base_log, level) // [level][n]
  let mut acc = _trlwe_zero(v.params)
  for j in 0..<level {
    let poly_da = digit_a[j]
    let poly_db = digit_b[j]

    // 上半：digit_a[j] * Enc(-s * μ_j)
    let mut all_zero = true
    for k in 0..<n {
      if poly_da[k] != 0 {
        all_zero = false
        break
      }
    }
    if !all_zero {
      let prod_a = _trlwe_mul_by_plain_poly(g.data[j], poly_da)
      acc = trlwe_ct_add(acc, prod_a)
    }

    // 下半：digit_b[j] * Enc( μ_j * 1 )
    all_zero = true
    for k in 0..<n {
      if poly_db[k] != 0 {
        all_zero = false
        break
      }
    }
    if !all_zero {
      let prod_b = _trlwe_mul_by_plain_poly(g.data[level + j], poly_db)
      acc = trlwe_ct_add(acc, prod_b)
    }
  }
  acc
}

// ===================== TRGSW 加密：Bool 版本（真正 H 结构） =====================
/// 对 bit=false: 返回 Enc(0) 的 TRGSW；
/// 对 bit=true : 返回“TRGSW_K(1)”，满足 external_product(G, Enc(m)) ≈ Enc(m)
pub fn trgsw_encrypt_bool(
  params : TrgswParams,
  key_tr : TrlweKey,
  bit : Bool,
  sigma : Float,
  rng : CsPrng,
) -> TrgswCiphertext {
  let level = params.level
  let base_log = params.base_log
  let n = params.n

  // 先全部填 Enc(0) 占位
  let data = Array::makei(2 * level, fn(_) {
    trlwe_encrypt_zero(params, key_tr, sigma, rng)
  })
  if !bit {
    return { params, data }
  }
  let base_mu : Int = T32_QUARTER // 2^30
  let _ : Int = 1 << base_log // B = 2^base_log

  // s(X) 明文多项式：系数 0/1
  let s_poly = trlwe_key_to_poly(key_tr)
  for j in 0..<level {
    let shift = base_log * j
    let mu_j = if shift >= 30 {
      // 防止右移过头变 0，做个保底
      1
    } else {
      base_mu >> shift
    }

    // ===== 上半块：Enc( -s(X) * mu_j ) =====
    let poly_top = Array::makei(n, fn(i) {
      if s_poly[i] != 0 {
        // -mu_j * s[i]
        t32_mul_k(mu_j, -1)
      } else {
        0
      }
    })
    data[j] = trlwe_encrypt(key_tr, poly_top, sigma, rng)

    // ===== 下半块：Enc( mu_j * 1 ) (常数多项式) =====
    let poly_bot = Array::makei(n, fn(i) { if i == 0 { mu_j } else { 0 } })
    data[level + j] = trlwe_encrypt(key_tr, poly_bot, sigma, rng)
  }
  { params, data }
}





///|
test "trgsw: external_product with bit=1 preserves encrypted bit0" {
  let r = csprng_new(0x20251127)
  let n = 512
  let base_log = 2
  let level = 3
  let _ : TrlweParams = { n, }
  let trgsw_params : TrgswParams = { base_log, level, n }
  let key_tr = trlwe_key_new(n, r)
  let sigma_trgsw : Float = 3.0
  let sigma_trlwe : Float = 3.0
  let g = trgsw_encrypt_bool(trgsw_params, key_tr, true, sigma_trgsw, r)
  let trials = 64
  let mut ok = 0
  for _t in 0..<trials {
    let bit_in = (next_u64(r) & 1) == 1
    let m_poly = trlwe_encode_bit_const(n, bit_in)
    let ct_msg = trlwe_encrypt(key_tr, m_poly, sigma_trlwe, r)
    let out = external_product(g, ct_msg)
    let mu_out = trlwe_decrypt_to_poly(key_tr, out)
    //println("bit=\{bit_in}  phase=\{mu_out[0]}")
    let bit_out = t32_decode_sign(mu_out[0])
    if bit_out == bit_in {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

test "debug: t32_decompose encode bits" {
  let base_log = 2
  let level    = 3
  let x_true   = T32_QUARTER        // encode_bit_const(true)[0]
  let x_false  = -T32_QUARTER       // encode_bit_const(false)[0]
  let _d_true   = t32_decompose_lsb_trgsw(x_true, base_log, level)
  let _d_false  = t32_decompose_lsb_trgsw(x_false, base_log, level)
  // 把 d_true/d_false 打印出来看一眼
  //println("d_true  =\{d_true}")
  //println("d_false =\{d_false}")
}


test "debug: decomp x_true vs mu_vec sum" {
  let base_log = 2
  let level = 3
  let x_true = T32_QUARTER
  let digits = t32_decompose_lsb_trgsw(x_true, base_log, level)
  let mu_vec = [1 << 31, 1 << 29, 1 << 27]
  let mut acc = 0
  for j in 0..<level {
    acc = acc + digits[j] * mu_vec[j]
  }
  //println("digits   = \{digits}")
  //println("recompose = \{acc}")
  assert_eq(acc.reinterpret_as_uint(), T32_HALF.reinterpret_as_uint())

}
