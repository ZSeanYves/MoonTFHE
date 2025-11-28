// ===================== TRGSW 参数与结构 =====================
///|
pub struct TrgswParams {
  base_log : Int // log_B，B = 2^base_log
  level : Int // ℓ
  n : Int // = TRLWE n (环维度 N)
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
fn gadget_decompose_poly(
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
fn trlwe_zero(params : TrlweParams) -> TrlweCiphertext {
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
fn trlwe_mul_by_plain_poly(
  ct : TrlweCiphertext,
  poly_plain : Array[Int],
) -> TrlweCiphertext {
  let n = ct.params.n
  let params = ct.params
  let mut acc = trlwe_zero(params)
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
  let digit_a = gadget_decompose_poly(v.a, base_log, level) // [level][n]
  let digit_b = gadget_decompose_poly(v.b, base_log, level) // [level][n]
  let mut acc = trlwe_zero(v.params)
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
      let prod_a = trlwe_mul_by_plain_poly(g.data[j], poly_da)
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
      let prod_b = trlwe_mul_by_plain_poly(g.data[level + j], poly_db)
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
    //////println("bit=\{bit_in}  phase=\{mu_out[0]}")
    let bit_out = t32_decode_sign(mu_out[0])
    if bit_out == bit_in {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

///|
test "debug: t32_decompose encode bits" {
  let base_log = 2
  let level = 3
  let x_true = T32_QUARTER // encode_bit_const(true)[0]
  let x_false = -T32_QUARTER // encode_bit_const(false)[0]
  let _d_true = t32_decompose_lsb_trgsw(x_true, base_log, level)
  let _d_false = t32_decompose_lsb_trgsw(x_false, base_log, level)
  // 把 d_true/d_false 打印出来看一眼
  //////println("d_true  =\{d_true}")
  //////println("d_false =\{d_false}")
}


///|
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
  //////println("digits   = \{digits}")
  //////println("recompose = \{acc}")
  assert_eq(acc.reinterpret_as_uint(), T32_HALF.reinterpret_as_uint())
}



///|
test "trgsw-learn-rule: external_product tiny, sigma=0" {
  let r = csprng_new(0x31415926)
  let n = 8 // 尽量小，方便看
  let base_log = 2
  let level = 3
  let _trlwe_params : TrlweParams = { n, }
  let trgsw_params : TrgswParams = { base_log, level, n }
  let key_tr = trlwe_key_new(n, r)

  // 噪声关掉，方便观察纯线性关系
  let sigma_trgsw : Float = 0.0
  let sigma_trlwe : Float = 0.0
  let g = trgsw_encrypt_bool(trgsw_params, key_tr, true, sigma_trgsw, r)
  let m_const_pos = Array::makei(n, fn(_i) { 0 })
  m_const_pos[0] = T32_QUARTER
  let m_const_neg = Array::makei(n, fn(_i) { 0 })
  m_const_neg[0] = -T32_QUARTER
  let k = 3
  let m_mono = Array::makei(n, fn(_i) { 0 })
  m_mono[k] = T32_QUARTER
  let ct_const_pos = trlwe_encrypt(key_tr, m_const_pos, sigma_trlwe, r)
  let ct_const_neg = trlwe_encrypt(key_tr, m_const_neg, sigma_trlwe, r)
  let ct_mono = trlwe_encrypt(key_tr, m_mono, sigma_trlwe, r)
  let out_const_pos = external_product(g, ct_const_pos)
  let out_const_neg = external_product(g, ct_const_neg)
  let out_mono = external_product(g, ct_mono)
  let _mu_const_pos = trlwe_decrypt_to_poly(key_tr, out_const_pos)
  let _mu_const_neg = trlwe_decrypt_to_poly(key_tr, out_const_neg)
  let _mu_mono = trlwe_decrypt_to_poly(key_tr, out_mono)
  //////println("m_const_pos in  = \{m_const_pos}")
  //////println("m_const_pos out = \{_mu_const_pos}")
  //////println("m_const_neg out = \{_mu_const_neg}")
  //////println("m_mono in       = \{m_mono}")
  //////println("m_mono out      = \{_mu_mono}")
}


/// 小参数下“反解” external_product 对明文多项式的线性作用 L
/// 这里我们取 n=8, base_log=2, level=3, sigma=0
/// 对每个基底多项式 e_j(X)=μ·X^j，测出 L(e_j) 解密后的系数。
test "trgsw-debug: learn_hidden_linear_kernel_tiny" {
  let r = csprng_new(0x20251128)
  let n = 8
  let base_log = 2
  let level = 3
  let tr_params : TrlweParams = { n, }
  let trgsw_params : TrgswParams = { base_log, level, n }

  // 生成 TRLWE 秘钥，用于构造 TRGSW 和后续解密
  let key_tr = trlwe_key_new(n, r)

  // 生成 G = TRGSW_1(1)，这里 sigma_bsk 先设为 0，去掉随机高斯噪声
  let sigma_trgsw : Float = 0.0
  let g = trgsw_encrypt_bool(trgsw_params, key_tr, true, sigma_trgsw, r)

  // μ = T32_QUARTER
  let mu : Int = T32_QUARTER
  // 因为你之前看到系数都是 μ 的 1/16 倍，这里取单位步长 = μ/16
  let step : Int = mu >> 4

  // mat[i][j] 代表：输入 e_j(X)=μ·X^j，解密输出 L(e_j) 的第 i 个系数，
  // 再除以 step，得到一个小整数，方便肉眼看模式
  let mat = Array::makei(n, fn(_i) { Array::makei(n, fn(_j) { 0 }) })
  for j in 0..<n {
    // 构造明文多项式 e_j(X) = μ · X^j
    let m = Array::makei(n, fn(_i) { 0 })
    m[j] = mu

    // 构造“明文 TRLWE”：a=0, b=m（不经过 trlwe_encrypt）
    let a0 = Array::makei(n, fn(_i) { 0 })
    let v : TrlweCiphertext = { params: tr_params, a: a0, b: m }

    // 做外积
    let out = external_product(g, v)

    // 用真正的 TRLWE 秘钥解密，得到 L(m)
    let lm = trlwe_decrypt_to_poly(key_tr, out)

    // 记录缩放后的小整数矩阵
    for i in 0..<n {
      let coeff = lm[i]
      // 四舍五入到最近的 step 倍数：k ≈ coeff / step
      let k = if step != 0 {
        // 手搓“向 0 取整”的除法，这里你也可以直接用除法看一眼
        coeff / step
      } else {
        0
      }
      mat[i][j] = k
    }
  }
  ////println("=== hidden linear kernel L (单位 step = μ/16) ===")
  for i in 0..<n {
    ////println("row \{i}: \{mat[i]}")
  }

  // 这里先不做 assert，只是把矩阵打印出来分析模式
}
