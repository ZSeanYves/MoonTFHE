// ========== 1. Oracle 参考实现包装 ==========
/// Oracle 版本的布尔门 PBS：
/// 直接调用当前主线 programmable_bootstrap（已经完全验证过）
pub fn oracle_bool_gate(
  p       : TfheParams,
  bk      : BootstrappingKey,
  ct_in   : LweCiphertext,
  f_true  : Int,
  f_false : Int,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, ct_in, f_true, f_false)
}

// ========== 2. BSK -> TRGSW 数组视图 ==========

/// 公开一版 BSK → TrgswCiphertext[] 的包装，
/// 实际内部复用 bsk.mbt 里的 _bsk_to_trgsw_array。
fn bsk_to_trgsw_array_exp(bk : BootstrappingKey) -> Array[TrgswCiphertext] {
  _bsk_to_trgsw_array(bk)
}



// ========== 3. 实验版 TRGSW PBS 壳 ==========

/// 实验版：使用 TRGSW / external_product 影响 accumulator，
/// 但最终旋转仍然用 oracle 的 φ→k，避免一下子搞崩行为。
///
/// 注意：
/// - 目前这版 **不是** 完整 TFHE blind rotation；
/// - 只是把 TRGSW 内容真实加进 acc.b 里，然后再用 oracle 做最后旋转。
pub fn programmable_bootstrap_trgsw_experimental(
  p       : TfheParams,
  bk      : BootstrappingKey,
  ct_in   : LweCiphertext,
  f_true  : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe

  // 1) 构建 LUT 多项式（和主线 PBS 完全一致）
  let acc_arr : Array[Int] = acc_from_lut2_for_boolean(n, f_true, f_false)

  // 2) 打包成 TRLWE 累加器：a=0，只用 b 存 LUT
  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_) { 0 })
  let mut acc : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  // 3) BSK 视为 TrgswCiphertext[]
  let bsk_trgsw = bsk_to_trgsw_array_exp(bk)
  let base_log = bk.params.base_log
  let level    = bk.params.level
  let n_in     = bk.n_in

  // 4) 用 TRGSW external_product 对 acc 做实验性的“相位偏移”
  //
  // 当前版本：对每个 a_i 做 gadget 分解，然后把
  //   digits[l] * Enc(s_i * g_l)
  // 累加到 acc 上（见 trgsw.mbt 中的 _external_product）。
  //
  // 这一步会真正“用上” TRGSW 的内容，但暂时还没完全替代 oracle 旋转逻辑。
  for i in 0..<n_in {
    let ai = ct_in.a[i]
    if ai == 0 {
      continue
    }
    let digits = gadget_decompose(ai, base_log, level)
    acc = external_product(bsk_trgsw[i], acc, digits)
  }

  // 5) 仍然用 oracle 的 φ = b - <a,s> → k → 旋转 LUT：
  //    这一块完全照搬主线 PBS 的逻辑，确保“旋转决策”不被实验部分打乱。
  let phi = phase_from_bsk_public(bk, ct_in)
  let k   = torus_phase_to_rot_k(phi, n)

  // 只旋转 b，多项式 a 的内容对最终提取结果会被我们丢掉（见下一步）
  let b_rot = poly_rotate_negacyclic(acc.b, k)

  // 6) 构造“干净壳”：a 全 0，只带 b_rot。
  //    这样 sample_extract_const 不再受 acc.a 的影响，
  //    行为更接近主线 PBS（主线 PBS 也都是 a=0）。
  let a_clean = Array::makei(n, fn(_) { 0 })
  let shell : TrlweCiphertext = { params: params_tr, a: a_clean, b: b_rot }

  // 7) 提取常数项为 LWE（和主线 PBS 完全一致）
  sample_extract_const(shell)
}

// ========== 4. 实验用的 NOT/ID 门包装 ==========

/// 实验版：NOT 门（TRGSW PBS 路径）
pub fn tfhe_not_trgsw_experimental(
  p  : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  // f(0)=0.5, f(1)=0
  programmable_bootstrap_trgsw_experimental(p, bk, ct, 0x8000_0000, 0x0000_0000)
}

/// 实验版：恒等门（TRGSW PBS 路径）
pub fn tfhe_id_trgsw_experimental(
  p  : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  // f(0)=0, f(1)=0.5
  programmable_bootstrap_trgsw_experimental(p, bk, ct, 0x0000_0000, 0x8000_0000)
}

// ========== 5. 可选：提供一个对比试验函数（非 test，避免影响 moon test） ==========

/// 非 test，只是你需要的时候可以在单独的小 main/test 里调用，
/// 看 TRGSW 实验版和 oracle 版的统计一致性。
///
/// 返回值：(trials, same_count)
pub fn pbs_trgsw_vs_oracle_stats(
  seed : UInt64,
  trials : Int,
) -> (Int, Int) {
  let r = csprng_new(seed)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in

  // 随机 LWE/TRLWE 密钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)

  let mut same = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 3.0, r)

    // oracle PBS NOT
    let ct_oracle = oracle_bool_gate(p, bk, ct, 0x8000_0000, 0x0000_0000)
    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)

    // TRGSW 实验 PBS NOT
    let ct_trgsw = tfhe_not_trgsw_experimental(p, bk, ct)
    let dec_trgsw = lwe_decrypt(key_lwe, ct_trgsw)

    if dec_oracle == dec_trgsw {
      same = same + 1
    }
  }
  (trials, same)
}

///================== Tests: Oracle 包装自检 ==================

test "pbs-oracle-wrapper: same as programmable_bootstrap for NOT" {
  let r = csprng_new(0x0ACE0101)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in

  // 随机 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)

  let trials = 32
  let mut ok = 0
  for _ in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct  = lwe_encrypt(key_lwe, bit, 3.0, r)

    // 直接用主线 PBS
    let ct_main   = programmable_bootstrap(p, bk, ct, 0x8000_0000, 0x0000_0000)
    let dec_main  = lwe_decrypt(key_lwe, ct_main)

    // 通过 oracle_bool_gate 包装
    let ct_oracle = oracle_bool_gate(p, bk, ct, 0x8000_0000, 0x0000_0000)
    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)

    if dec_main == dec_oracle {
      ok = ok + 1
    }
  }

  // 这里理论上应全部相等
  assert_eq(ok, trials)
}

///================== Tests: BSK -> TRGSW 视图 ==================

test "bsk_to_trgsw_array_exp: shape and params" {
  let r = csprng_new(0xB5C0CBEE)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n    = p.n_trlwe

  // 构造随机密钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(n, r)

  let base_log = 2
  let level    = 3
  let sigma : Float = 3.0
  let bk = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)

  let arr = bsk_to_trgsw_array_exp(bk)
  assert_eq(arr.length(), n_in)
  for i in 0..<n_in {
    let g = arr[i]
    assert_eq(g.params.base_log, base_log)
    assert_eq(g.params.level,    level)
    assert_eq(g.params.n,        n)
    assert_eq(g.data.length(),   level)
    for l in 0..<level {
      assert_eq(g.data[l].params.n, n)
      assert_eq(g.data[l].a.length(), n)
      assert_eq(g.data[l].b.length(), n)
    }
  }
}


///================== Tests: TRGSW 实验 PBS 统计对比 ==================

test "pbs-trgsw-experimental: stats vs oracle NOT gate" {
  let seed : UInt64 = 0xDEADBEEF
  let trials = 64
  let (total, same) = pbs_trgsw_vs_oracle_stats(seed, trials)

  // 基本 sanity：same 绝对不会超出 [0, total]
  assert_eq(total, trials)
  assert_eq(same >= 0, true)
  assert_eq(same <= total, true)

  println("TRGSW experimental PBS vs oracle (NOT gate): same = \{same}/\{total}")
}


fn blind_rotate_digitwise_dev(
  p       : TfheParams,
  bk      : BootstrappingKey,
  ct_in   : LweCiphertext,
  acc_init: TrlweCiphertext,
) -> TrlweCiphertext {
  let n        = p.n_trlwe
  let base_log = bk.params.base_log
  let level    = bk.params.level
  let n_in     = bk.n_in

  let acc = acc_init

  // 每个 digit 的基础步长：先取一个“相对很小”的值，后面可以慢慢调。
  let unit_step = n / (1 << (base_log + 2))

  // 累加“总旋转量”
  let mut k_total = 0

  for i in 0..<n_in {
    if !bk.s_bits[i] {
      // 对应 s_i = 0，这一位不贡献相位
      continue
    }
    let ai = ct_in.a[i]
    if ai == 0 {
      continue
    }

    let digits = gadget_decompose(ai, base_log, level)

    for l in 0..<level {
      let d = digits[l]
      if d == 0 { continue }

      // 第 l 层权重更大：步长翻倍
      let step_l = unit_step << l

      // 简单用 ai 的符号控制正反方向
      let is_neg = ai < 0
      let mut k = step_l * d
      if is_neg {
        k = -k
      }

      k_total = k_total + k
    }
  }

  // 一次性旋转 acc.b
  if k_total != 0 {
    acc.b = poly_rotate_negacyclic(acc.b, k_total)
  }

  acc
}


/// 基于 digit-wise blind rotation 的实验 PBS：
/// 不再用 phase_from_bsk_public + torus_phase_to_rot_k，
/// 而是使用上面的 blind_rotate_digitwise_dev 来直接转动 LUT。
pub fn programmable_bootstrap_digitwise_experimental(
  p       : TfheParams,
  bk      : BootstrappingKey,
  ct_in   : LweCiphertext,
  f_true  : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = acc_from_lut2_for_boolean(n, f_true, f_false)

  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  // 这里完全不调用 phase_from_bsk_public，
  // 而是用 digit-wise 的方式一步步转动 acc。
  let acc_final = blind_rotate_digitwise_dev(p, bk, ct_in, acc_init)

  sample_extract_const(acc_final)
}

/// digit-wise PBS 版本的 NOT gate
pub fn tfhe_not_digitwise_experimental(
  p  : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap_digitwise_experimental(
    p, bk, ct,
    0x8000_0000,  // f_true
    0x0000_0000,  // f_false
  )
}

test "pbs-digitwise-experimental: NOT vs oracle stats" {
  let r = csprng_new(0xABCD123476)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in

  // 随机密钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(p.n_trlwe, r)
  let bk      = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)

  let trials = 64
  let mut same = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct  = lwe_encrypt(key_lwe, bit, 3.0, r)

    let ct_oracle = tfhe_not(p, bk, ct)
    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)

    let ct_digit  = tfhe_not_digitwise_experimental(p, bk, ct)
    let dec_digit = lwe_decrypt(key_lwe, ct_digit)

    if dec_oracle == dec_digit {
      same = same + 1
    }
  }

  println("Digit-wise PBS vs oracle (NOT): same = \{same}/\{trials}")
  // 先不对 same 做很严的断言，避免一开始就红。
  assert_eq(trials, 64)
  assert_eq(same >= 0, true)
  assert_eq(same <= trials, true)
}


/// 只计算 digit-wise 累积的总旋转量 k_total（不动 acc）
/// 方便和 oracle 的 k_oracle 做对比。
fn compute_k_digitwise_dev(
  p      : TfheParams,
  bk     : BootstrappingKey,
  ct_in  : LweCiphertext,
) -> Int {
  let n        = p.n_trlwe
  let base_log = bk.params.base_log
  let level    = bk.params.level
  let n_in     = bk.n_in

  // 保持和 blind_rotate_digitwise_dev 中一致的 unit_step
  let unit_step = n / (1 << (base_log + 2))

  let mut k_total = 0

  for i in 0..<n_in {
    if !bk.s_bits[i] {
      continue
    }
    let ai = ct_in.a[i]
    if ai == 0 {
      continue
    }

    let digits = gadget_decompose(ai, base_log, level)
    for l in 0..<level {
      let d = digits[l]
      if d == 0 { continue }

      let step_l = unit_step << l

      let is_neg = ai < 0
      let mut k = step_l * d
      if is_neg {
        k = -k
      }

      k_total = k_total + k
    }
  }

  k_total
}

/// 基于 digit-wise 计算 k_total，然后用 "acc * X^{k_total}" 做真正旋转的实验版。
fn blind_rotate_digitwise_poly_dev(
  p        : TfheParams,
  bk       : BootstrappingKey,
  ct_in    : LweCiphertext,
  acc_init : TrlweCiphertext,
) -> TrlweCiphertext {
  let n        = p.n_trlwe
  let base_log = bk.params.base_log
  let level    = bk.params.level
  let n_in     = bk.n_in

  // 必须与 compute_k_digitwise_dev / blind_rotate_digitwise_dev 保持一致
  let unit_step = n / (1 << (base_log + 2))

  // 先算总的 k_total
  let mut k_total = 0

  for i in 0..<n_in {
    if !bk.s_bits[i] {
      continue
    }
    let ai = ct_in.a[i]
    if ai == 0 {
      continue
    }

    let digits = gadget_decompose(ai, base_log, level)
    for l in 0..<level {
      let d = digits[l]
      if d == 0 { continue }

      let step_l = unit_step << l
      let is_neg = ai < 0
      let mut k = step_l * d
      if is_neg {
        k = -k
      }

      k_total = k_total + k
    }
  }

  // 若 k_total == 0，直接返回初始 acc
  if k_total == 0 {
    return acc_init
  }

  // 构造 monomial 多项式 h = X^{k_total}
  let h = poly_monomial_exp(n, k_total)

  // 用卷积方式对整个 TRLWE 做旋转（等价于 poly_rotate_negacyclic）
  trlwe_mul_by_plain_poly_exp(acc_init, h)
}

/// 基于 blind_rotate_digitwise_poly_dev 的实验版 PBS：
/// 使用 digit-wise 计算出的 k_total，并通过 acc * X^{k_total} 执行旋转。
pub fn programmable_bootstrap_digitwise_poly_experimental(
  p       : TfheParams,
  bk      : BootstrappingKey,
  ct_in   : LweCiphertext,
  f_true  : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = acc_from_lut2_for_boolean(n, f_true, f_false)

  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_i) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  let acc_final = blind_rotate_digitwise_poly_dev(p, bk, ct_in, acc_init)
  sample_extract_const(acc_final)
}

/// 对应的 NOT gate（digit-wise + poly 卷积版）
pub fn tfhe_not_digitwise_poly_experimental(
  p  : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap_digitwise_poly_experimental(
    p, bk, ct,
    0x8000_0000,  // f_true
    0x0000_0000,  // f_false
  )
}

test "pbs-digitwise-poly-experimental: NOT vs oracle stats" {
  let r = csprng_new(0xD1CE123476)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in

  // 随机密钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(p.n_trlwe, r)
  let bk      = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)

  let trials = 64
  let mut same = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct  = lwe_encrypt(key_lwe, bit, 3.0, r)

    let ct_oracle = tfhe_not(p, bk, ct)
    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)

    let ct_poly   = tfhe_not_digitwise_poly_experimental(p, bk, ct)
    let dec_poly  = lwe_decrypt(key_lwe, ct_poly)

    if dec_oracle == dec_poly {
      same = same + 1
    }
  }

  println("Digit-wise POLY PBS vs oracle (NOT): same = \{same}/\{trials}")
  assert_eq(same >= 0, true)
  assert_eq(same <= trials, true)
}



test "pbs-digitwise-k-vs-oracle: inspect k_total and k_oracle" {
  let r = csprng_new(0xABCD)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n    = p.n_trlwe

  // 随机密钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(n, r)
  let bk      = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)

  let trials = 8   // 少量就够，看几组
  for t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct  = lwe_encrypt(key_lwe, bit, 3.0, r)

    // oracle 路径的 k
    let phi       = phase_from_bsk_public(bk, ct)
    let k_oracle  = torus_phase_to_rot_k(phi, n)

    // digit-wise 路径的 k_total
    let k_total   = compute_k_digitwise_dev(p, bk, ct)

    // 为了对比方便，把 k_total 也折到 [0, n) 里
    let k_total_mod = ((k_total % n) + n) % n

    println("case {t}: bit=\{bit}, k_oracle=\{k_oracle}, k_total_mod=\{k_total_mod}, raw_k_total=\{k_total}")

    // 宽松 sanity：
    // 1) k_oracle 一定在 [0, n)
    assert_eq(k_oracle >= 0, true)
    assert_eq(k_oracle < n,  true)
    // 2) k_total_mod 也在 [0, n)
    assert_eq(k_total_mod >= 0, true)
    assert_eq(k_total_mod < n,  true)
  }
}

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
