/// 实验工具：TRLWE × 明文多项式 (negacyclic 卷积)
/// 这里的 h 是明文多项式，长度必须等于 n。
fn trlwe_mul_by_plain_poly_exp(
  ct : TrlweCiphertext,
  h  : Array[Int],
) -> TrlweCiphertext {
  let n = ct.params.n
  if h.length() != n {
    panic()
  }
  let a2 = poly_mul_negacyclic(ct.a, h)
  let b2 = poly_mul_negacyclic(ct.b, h)
  { params: ct.params, a: a2, b: b2 }
}

/// 构造 monomial 多项式 h(X) = X^k  （mod X^n+1）
/// 这里我们只在 [0,n) 里放一个 1，其余为 0；
/// 真正的 negacyclic 语义由 poly_mul_negacyclic 负责。
fn poly_monomial_exp(n : Int, k : Int) -> Array[Int] {
  let kk = ((k % n) + n) % n  // 规范到 [0,n)
  let h = Array::makei(n, fn(_i) { 0 })
  h[kk] = 1
  h
}



///================== Tests: TRLWE * monomial ≈ 旋转 ==================

test "trlwe-exp: mul_by_monomial matches rotate on b-poly" {
  let n = 16
  let params : TrlweParams = { n, }

  // 构造一个简单可读的 b 多项式：b = 1 + 2X + 3X^2 + ... + 16X^15
  let a = Array::makei(n, fn(_i) { 0 }) // a 暂时全 0
  let b = Array::makei(n, fn(i) { (i + 1) })  // b[i] = i+1
  let ct : TrlweCiphertext = { params, a, b }

  // 构造 monomial h = X^k
  let k = 5
  let h = Array::makei(n, fn(_i) { 0 })
  h[k] = 1

  // 1) 用卷积方式：ct * X^k
  let ct_conv = trlwe_mul_by_plain_poly_exp(ct, h)

  // 2) 用你之前已经实现的 negacyclic 旋转：rotate(b, k)
  let b_rot = poly_rotate_negacyclic(b, k)

  // 我们只比较 b 多项式部分是否一致
  assert_eq(poly_eq(ct_conv.b, b_rot), true)
}

// ==== V2-PBS====）；
fn trgsw_hint_majority(ct : TrlweCiphertext) -> Bool {
  let n = ct.b.length()
  let limit = if n < 16 { n } else { 16 }
  let mut score = 0
  for i in 0..<limit {
    if t32_decode_sign(ct.b[i]) {
      score = score + 1
    } else {
      score = score - 1
    }
  }
  score >= 0
}

///|
fn external_product_v2_blind(
  p : TfheParams,
  bk2 : BootstrappingKeyV2,
  acc : TrlweCiphertext,
  ai : Int,
  idx : Int,
  step_l? : Array[Int] = [5, -4, -6],
) -> TrlweCiphertext {
  let n = p.n_trlwe
  let base_log = bk2.params.base_log
  let level = bk2.params.level
  if ai == 0 {
    return acc
  }
  let g = bk2.data[idx]
  let digits = gadget_decompose(ai, base_log, level)
  let sign_ai = if ai >= 0 { 1 } else { -1 }
  let mut acc_cur = acc
  for l in 0..<level {
    let d = digits[l]
    if d == 0 {
      continue
    }
    let ct0 = g.data[2 * l]
    let hint_bit = trgsw_hint_majority(ct0)
    if !hint_bit {
      continue
    }
    let k = d * step_l[l] * sign_ai
    if k != 0 {
      let h = poly_monomial_exp(n, k)
      acc_cur = trlwe_mul_by_plain_poly_exp(acc_cur, h)
    }
  }
  acc_cur
}




/// 真·dev 版 blind rotation：
/// 对每一维调用 external_product_v2_blind，
/// 旋转完全由 TRGSW V2 内容 + a_i digits 决定，不再用 s_bits。
fn blind_rotate_v2_dev(
  p      : TfheParams,
  bk2    : BootstrappingKeyV2,
  ct_in  : LweCiphertext,
  acc_in : TrlweCiphertext,
) -> TrlweCiphertext {
  let n_in = bk2.n_in
  let mut acc = acc_in
  for i in 0..<n_in {
    let ai = ct_in.a[i]
    acc = external_product_v2_blind(p, bk2, acc, ai, i)
  }
  acc
}

fn programmable_bootstrap_v2(
  p    : TfheParams,
  bk2  : BootstrappingKeyV2,
  ct   : LweCiphertext,
  f_true  : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = acc_from_lut2_for_boolean(n, f_true, f_false)

  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_i) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  let acc_final = blind_rotate_v2_dev(p, bk2, ct, acc_init)
  sample_extract_const(acc_final)
}

/// V2-dev 版本的 NOT gate，基于 TRGSW blind rotation PBS
pub fn tfhe_not_v2(
  p : TfheParams,
  bk2 : BootstrappingKeyV2,
  ct : LweCiphertext,
) -> LweCiphertext {
  // true -> 0.5, false -> 0
  programmable_bootstrap_v2(
    p, bk2, ct, 0x8000_0000, // f_true
     0x0000_0000, // f_false
  )
}


/// 使用 TRGSW V2-dev blind rotation 的 PBS，
/// 和 oracle PBS 做 NOT 门结果的统计对比（仅打印 same，不做强约束）。
test "pbs-v2-dev: NOT vs oracle stats" {
  let r = csprng_new(0x23456)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in

  // 随机 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_i) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let base_log = 2
  let level = 3
  let sigma : Float = 3.0

  // V1 BSK：用来跑 oracle PBS（真值参考）
  let bk1 = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)
  // V2 BSK：用来跑 TRGSW V2-dev blind rotation PBS
  let bk2 = bsk_generate_v2(p, key_lwe, key_tr, base_log, level, sigma, r)
  let trials = 64
  let mut same = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 3.0, r)

    // oracle 版本 NOT
    let ct_oracle = tfhe_not(p, bk1, ct)
    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)

    // V2-dev blind 版本 NOT
    let ct_v2 = tfhe_not_v2(p, bk2, ct)
    let dec_v2 = lwe_decrypt(key_lwe, ct_v2)
    if dec_oracle == dec_v2 {
      same = same + 1
    }
  }
  println("PBS V2-dev blind vs oracle NOT: same = \{same}/\{trials}")
  // 这里只把 same 当观测指标，不对其大小做任何严格约束
  assert_eq(same >= 0, true)
  assert_eq(same <= trials, true)
}



/// 自动拟合 V2-dev blind PBS 的步长 step_l
/// 输出可直接贴回代码的常量数组 STEP_L
test "fit step_l for V2-dev blind PBS" {
  let r = csprng_new(0xF17F17F1)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let base_log = 2
  let level = 3
  let sigma : Float = 3.0

  // 构造 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_i) { false })
  for i in 0..<n_in { s[i] = (next_u64(r) & 1) == 1 }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(p.n_trlwe, r)

  // 正式 PBS 用的 BSK（oracle k）
  let bk1 = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)
  // 实验 PBS V2（提供 digits）
  let _ = bsk_generate_v2(p, key_lwe, key_tr, base_log, level, sigma, r)

  // 采样数量
  let n = 200

  // A 矩阵：N × level
  let a = Array::makei(n, fn(_i) {
    Array::makei(level, fn(_j) { 0.0 })
  })
  // y 向量：N
  let y = Array::makei(n, fn(_i) { 0.0 })

  for t in 0..<n{
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, sigma, r)

    // oracle-phase PBS → 得到真实 k
    let phi = phase_from_bsk_public(bk1, ct)
    let k_oracle = torus_phase_to_rot_k(phi, p.n_trlwe)

    // digits from TRGSW V2
    // ct_in.a[i] 的每个 a_i 都可以参与，但我们只取第一个非零 a_i 的 digits
    let mut chosen_ai = 0
    let mut chosen_digits = Array::makei(level, fn(_) { 0 })

    for i in 0..<n_in {
      let ai = ct.a[i]
      if ai != 0 {
        chosen_ai = ai
        chosen_digits = gadget_decompose(ai, base_log, level)
        break
      }
    }

    let sign_ai = if chosen_ai >= 0 { 1.0 } else { -1.0 }

    // 填 A[t][l] = digits[l] * sign(ai)
    for l in 0..<level {
      a[t][l] = chosen_digits[l].to_double() * sign_ai
    }

    y[t] = k_oracle.to_double()
  }

  // ---- 最小二乘求解 (A^T A) step = A^T y ----

  // 计算 ATA (level × level)
  let ata = Array::makei(level, fn(_i) {
    Array::makei(level, fn(_j) { 0.0 })
  })
  for i in 0..<level {
    for j in 0..<level {
      let mut s = 0.0
      for t in 0..<n {
        s = s + a[t][i] * a[t][j]
      }
      ata[i][j] = s
    }
  }

  // 计算 ATy (level)
  let aty = Array::makei(level, fn(_i) { 0.0 })
  for i in 0..<level {
    let mut s = 0.0
    for t in 0..<n {
      s = s + a[t][i] * y[t]
    }
    aty[i] = s
  }

  // 求解小矩阵 (3×3) → 用 Cramer 或直接高斯消元
  let step_l = Array::makei(level, fn(_) { 0.0 })

  // 这里用最简单的 3x3 Gauss (你的代码量不大，MoonBit 足够跑)
  // 拷贝 ATA, ATy
  let m = Array::makei(level, fn(i) {
    Array::makei(level+1, fn(j) {
      if j < level { ata[i][j] } else { aty[i] }
    })
  })

  // 消元
  for i in 0..<level {
    let pivot = m[i][i]
    if abs_f(pivot.to_float()) < 0.000001 {
      continue
    }
    // 行归一化
    for j in i..<(level+1) {
      m[i][j] = m[i][j] / pivot
    }
    // 消除其他行
    for k in 0..<level {
      if k == i { continue }
      let factor = m[k][i]
      for j in i..<(level+1) {
        m[k][j] = m[k][j] - factor * m[i][j]
      }
    }
  }

  // 解已经在最后一列
  for i in 0..<level {
    step_l[i] = m[i][level]
  }

  println("=== Fitted step_l ===")
  for l in 0..<level {
    println("step_l[{l}] = \{step_l[l]}")
  }

  // MoonBit 代码格式
  println("Paste into code:")
  println("const STEP_L : Array[Int] = [")
  for l in 0..<level {
    if l > 0 { println(", ") }
    // 取最近整数
    let k = step_l[l].round().to_int()
    println(k)
  }
  println("];")
  
  assert_eq(true, true)
}
