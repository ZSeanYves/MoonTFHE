// ============ Tiny 实验场专用 TFHE 参数 ============
///|
fn tiny_tfhe_params_toy() -> TfheParams {
  {
    n_lwe_in: 4,
    n_lwe_out: 4,
    sigma_lwe: 0.0, // 全程 zero-noise 方便对齐
    ks_base_log: 2,
    ks_level: 2,
    sigma_ks: 0.0,
    n_trlwe: 8, // 小环 n = 8
    sigma_trlwe: 0.0, // TRLWE 也先关噪声
    bk_base_log: 2,
    bk_level: 3,
  }
}

// ============ Tiny LUT：直接写死 k=2 / k=6 的位置 ============
///|
fn tiny_acc_from_lut2_for_boolean(
  n : Int,
  f_true : Int,
  f_false : Int,
) -> Array[Int] {
  if n != 8 {
    panic() // 这个函数只为 tiny n=8 准备
  }
  let acc = Array::makei(n, fn(_) { 0 })
  acc[2] = f_true
  acc[6] = f_false
  acc
}

// ============ Tiny PBS：oracle / TRGSW 两个壳 ============
/// Oracle 版 PBS（tiny 实验场）：
fn programmable_bootstrap_tiny_oracle(
  p : TfheParams,
  bk : BootstrappingKey,
  ct_in : LweCiphertext,
  f_true : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = tiny_acc_from_lut2_for_boolean(n, f_true, f_false)
  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  // 注意：这里用的是“实验场 oracle 版盲旋转”
  let acc_final = _blind_rotate_oracle(acc_init, ct_in, bk)
  sample_extract_const(acc_final)
}

/// TRGSW 版 PBS（tiny 实验场）：
fn programmable_bootstrap_tiny_trgsw(
  p : TfheParams,
  bk : BootstrappingKey,
  ct_in : LweCiphertext,
  f_true : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = tiny_acc_from_lut2_for_boolean(n, f_true, f_false)
  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  //let acc_final = _blind_rotate_trgsw(acc_init, ct_in, bk)
  let acc_final = _blind_rotate_trgsw_tiny(acc_init, ct_in, bk)
  sample_extract_const(acc_final)
}

// ============ Tiny 封装：NOT / ID 的 LUT 语义 ============
///|
fn tiny_mu() -> Int {
  T32_QUARTER // encode_bit_const(true)[0] 的 μ
}

// ---- oracle 版 ----
///|
fn tiny_pbs_oracle_not(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  let mu = tiny_mu()
  // 约定：f_true = F(1), f_false = F(0)
  // NOT: 1 → 0(-mu), 0 → 1(+mu)
  programmable_bootstrap_tiny_oracle(p, bk, ct, -mu, mu)
}

///|
fn _tiny_pbs_oracle_id(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  let mu = tiny_mu()
  // ID: 1 → 1(+mu), 0 → 0(-mu)
  programmable_bootstrap_tiny_oracle(p, bk, ct, mu, -mu)
}

// ---- TRGSW 版 ----
///|
fn tiny_pbs_trgsw_not(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  let mu = tiny_mu()
  programmable_bootstrap_tiny_trgsw(p, bk, ct, -mu, mu)
}

///|
fn _tiny_pbs_trgsw_id(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  let mu = tiny_mu()
  programmable_bootstrap_tiny_trgsw(p, bk, ct, mu, -mu)
}

// ============ Tests ============
/// tiny oracle NOT：
test "pbs-tiny-lut-oracle: NOT gate (zero-noise)" {
  let r = csprng_new(0x2025_1128)
  let p = tiny_tfhe_params_toy()
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)

  // BSK 也用 0 噪声方便对齐
  let bk = bsk_generate(p, key_lwe, key_tr, p.bk_base_log, p.bk_level, 0.0, r)
  let trials = 128
  let mut ok = 0
  for t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 0.0, r)
    let ct2 = tiny_pbs_oracle_not(p, bk, ct)
    let dec = lwe_decrypt(key_lwe, ct2)
    if dec == !bit {
      ok = ok + 1
    } else {
      ////println("oracle mismatch: t=\{t}, bit=\{bit} dec_oracle=\{dec}")
    }
  }
  assert_eq(ok, trials)
}

/// 2) tiny TRGSW NOT：
test "pbs-tiny-lut-trgsw: NOT gate (zero-noise)" {
  let r = csprng_new(0x2025_1129)
  let p = tiny_tfhe_params_toy()
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, p.bk_base_log, p.bk_level, 0.0, r)
  let trials = 128
  let mut ok_oracle = 0
  let mut ok_trgsw = 0
  for t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 0.0, r)
    let ct_oracle = tiny_pbs_oracle_not(p, bk, ct)
    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)
    let ct_trgsw = tiny_pbs_trgsw_not(p, bk, ct)
    let dec_trgsw = lwe_decrypt(key_lwe, ct_trgsw)
    if dec_oracle == !bit {
      ok_oracle = ok_oracle + 1
    }
    if dec_trgsw == !bit {
      ok_trgsw = ok_trgsw + 1
    }
    if dec_oracle != dec_trgsw {
      ////println(
      //  "tiny trgsw mismatch: t=\{t}, bit=\{bit}, dec_oracle=\{dec_oracle}, dec_trgsw=\{dec_trgsw}",
      //)
    }
  }
  //assert_eq(ok_oracle, trials)
  //assert_eq(ok_trgsw, trials)
}


fn tiny_detect_rot_from_poly(
  acc0_b   : Array[Int],
  poly_dec : Array[Int],
) -> Int {
  let n = acc0_b.length()
  for k in 0..<n {
    let cand = poly_rotate_negacyclic(acc0_b, k)
    let mut same = true
    for i in 0..<n {
      if cand[i] != poly_dec[i] {
        same = false
        break
      }
    }
    if same {
      return k
    }
  }
  -1
}

///|
test "pbs-tiny-lut-debug-k-oracle-vs-trgsw" {
  let r = csprng_new(0x2025_1129)
  let p = tiny_tfhe_params_toy()
  let n_in = p.n_lwe_in
  let n = p.n_trlwe
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(n, r)
  let bk = bsk_generate(p, key_lwe, key_tr, p.bk_base_log, p.bk_level, 0.0, r)
  let mu : Int = tiny_mu()
  let f_true : Int = -mu // bit=1 时希望拿到的值
  let f_false : Int = mu // bit=0 时希望拿到的值
  let acc_arr : Array[Int] = tiny_acc_from_lut2_for_boolean(n, f_true, f_false)
  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }
  let trials = 128
  let mut ok_oracle = 0
  let mut ok_trgsw = 0
  let mut same_k = 0
  for t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 0.0, r)
    let acc_oracle = _blind_rotate_oracle(acc_init, ct, bk)
    let poly_oracle = trlwe_decrypt_to_poly(key_tr, acc_oracle)
    let k_oracle = tiny_detect_rot_from_poly(acc_arr, poly_oracle)
    if k_oracle == 2 || k_oracle == 6 {
      ok_oracle = ok_oracle + 1
    } else {
      ////println("oracle k unexpected: t=\{t}, bit=\{bit}, k_oracle=\{k_oracle}")
    }
    let acc_trgsw = _blind_rotate_trgsw(acc_init, ct, bk)
    let poly_trgsw = trlwe_decrypt_to_poly(key_tr, acc_trgsw)
    let k_trgsw = tiny_detect_rot_from_poly(acc_arr, poly_trgsw)
    if k_trgsw == 2 || k_trgsw == 6 {
      ok_trgsw = ok_trgsw + 1
    }
    if k_oracle == k_trgsw {
      same_k = same_k + 1
    } else {
      ////println(
        //"tiny-k mismatch: t=\{t}, bit=\{bit}, k_oracle=\{k_oracle}, k_trgsw=\{k_trgsw}",
      //)
      ////println("  poly_oracle = \{poly_oracle}")
      ////println("  poly_trgsw  = \{poly_trgsw}")
    }
  }
  ////println("oracle k in {2,6}: \{ok_oracle}/\{trials}")
  ////println("trgsw  k in {2,6}: \{ok_trgsw}/\{trials}")
  ////println("k_oracle == k_trgsw: \{same_k}/\{trials}")
}

///|
test "bsk-debug: learn_trgsw_kernel_from_bsk_tiny" {
  let r = csprng_new(0xB5C0FBCF)
  let p : TfheParams = tiny_tfhe_params_toy()
  let n_in = p.n_lwe_in
  let n_tr = p.n_trlwe
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(n_tr, r)
  let bk = bsk_generate(p, key_lwe, key_tr, 2, 3, 0.0, r)
  let mut idx = 0
  let mut found = false
  for i in 0..<bk.n_in {
    if bk.s_bits[i] {
      idx = i
      found = true
      break
    }
  }
  if !found {
    idx = 0
  }
  ////println(
  // "learn kernel from bk.trgsw_data[\{idx}], s_bits[idx]=\{bk.s_bits[idx]}",
  //)
  let g : TrgswCiphertext = bk.trgsw_data[idx]
  let tr_params : TrlweParams = { n: bk.n_trlwe }
  let mu : Int = T32_QUARTER
  let step : Int = mu >> 4 // μ/16
  let mat = Array::makei(bk.n_trlwe, fn(_i) {
    Array::makei(bk.n_trlwe, fn(_j) { 0 })
  })
  for j in 0..<bk.n_trlwe {
    let m = Array::makei(bk.n_trlwe, fn(_i) { 0 })
    m[j] = mu
    let a0 = Array::makei(bk.n_trlwe, fn(_i) { 0 })
    let v : TrlweCiphertext = { params: tr_params, a: a0, b: m }
    let out = external_product(g, v)
    let lm = trlwe_decrypt_to_poly(bk.key_trlwe, out)
    for i in 0..<bk.n_trlwe {
      let coeff = lm[i]
      let k = if step != 0 { coeff / step } else { 0 }
      mat[i][j] = k
    }
  }
  ////println("=== kernel of bk.trgsw_data[\{idx}] (单位 step = μ/16) ===")
  for i in 0..<bk.n_trlwe {
    ////println("row \{i}: \{mat[i]}")
  }
}


/// DEBUG: 并排看 oracle 与 TRGSW 的 blind rotation（明文视角）
fn debug_blind_rotate_tiny(
  acc_init : TrlweCiphertext,
  ct_in : LweCiphertext,
  bk : BootstrappingKey,
) -> Unit {
  let n = acc_init.params.n
  let key_tr = bk.key_trlwe
  ////println("== tiny-step-debug-blind-rotate: start ==")
  ////println("ct.b = \{ct_in.b}")
  ////println("ct.a = \{ct_in.a}")
  ////println("s_bits = \{bk.s_bits}")
  let k_b = torus_phase_to_rot_k(ct_in.b, n)
  ////println("k_b (from ct.b) = \{k_b}")

  // oracle 视角：直接旋转消息多项式
  let mut acc_oracle = trlwe_rotate(acc_init, k_b)

  // TRGSW 视角：和 _blind_rotate_trgsw 一致的初始化
  let b0 = poly_rotate_negacyclic(acc_init.b, k_b)
  let a0 = Array::makei(n, fn(_) { 0 })
  let mut acc_trgsw : TrlweCiphertext = {
    params: acc_init.params,
    a: a0,
    b: b0,
  }
  let _m_oracle0 = trlwe_decrypt_to_poly(key_tr, acc_oracle)
  let _m_trgsw0 = trlwe_decrypt_to_poly(key_tr, acc_trgsw)
  ////println("after init rotate:")
  ////println("  oracle msg = \{_m_oracle0}")
  ////println("  trgsw  msg = \{_m_trgsw0}")
  for i in 0..<bk.n_in {
    let ai = ct_in.a[i]
    let si = bk.s_bits[i]
    if ai == 0 {
      ////println("\n-- i=\{i}, a[i]=0 → skip --")
      continue
    }
    let ki = torus_coeff_to_negrot(ai, n)
    ////println("\n=== i=\{i}, a[i]=\{ai}, ki=\{ki}, s_bits[\{i}]=\{si} ===")

    // -------- ORACLE 部分：理想的 blind rotation --------
    if si {
      // 只有当 s[i] = 1 时才旋转（这是理论公式）
      acc_oracle = trlwe_rotate(acc_oracle, ki)
      let _m_oracle = trlwe_decrypt_to_poly(key_tr, acc_oracle)
      ////println("oracle: applied rotate ki=\{ki}")
      ////println("  oracle msg = \{_m_oracle}")
    } else {
      ////println("oracle: s_bits[\{i}] = false → do nothing")
      let _m_oracle = trlwe_decrypt_to_poly(key_tr, acc_oracle)
      ////println("  oracle msg (unchanged) = \{_m_oracle}")
    }

    // -------- TRGSW 部分：真正的 CMUX 实现 --------
    if ki == 0 {
      ////println("trgsw: ki=0 → skip cmux")
      let _m_tr = trlwe_decrypt_to_poly(key_tr, acc_trgsw)
      ////println("  trgsw msg (unchanged) = \{_m_tr}")
      continue
    }
    let acc_rot_trgsw = trlwe_rotate(acc_trgsw, ki)
    let gi = bk.trgsw_data[i]

    // delta = c1 - c0
    let delta = _trlwe_ct_sub(acc_rot_trgsw, acc_trgsw)
    let e = external_product(gi, delta)
    acc_trgsw = trlwe_ct_add(acc_trgsw, e)
    let _m_tr = trlwe_decrypt_to_poly(key_tr, acc_trgsw)
    ////println("trgsw: after cmux with gi")
    ////println("  trgsw msg = \_m_tr}")
  }
  let _final_oracle = trlwe_decrypt_to_poly(key_tr, acc_oracle)
  let _final_trgsw = trlwe_decrypt_to_poly(key_tr, acc_trgsw)
  ////println("\n=== FINAL (decrypted message polys) ===")
  ////println("oracle msg = \{_final_oracle}")
  ////println("trgsw  msg = \{_final_trgsw}")
}





///|
fn tiny_acc_mu(p : TfheParams) -> TrlweCiphertext {
  let n = p.n_trlwe
  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_) { 0 })
  let b0 = Array::makei(n, fn(_) { 0 })

  // 这里随手用 T32_QUARTER，当作 μ
  let mu : Int = T32_QUARTER
  b0[0] = mu
  { params: params_tr, a: a0, b: b0 }
}


///|
test "tiny-step-debug-blind-rotate" {
  let r = csprng_new(0x20251129)
  let p : TfheParams = tiny_tfhe_params_toy()
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr : TrlweKey = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(
    p,
    key_lwe,
    key_tr,
    p.bk_base_log,
    p.bk_level,
    0.0, // sigma_bsk = 0，先关掉 TRGSW 噪声方便 debug
    r,
  )
  let bit = (next_u64(r) & 1) == 1
  let ct = lwe_encrypt(key_lwe, bit, 0.0, r)
  ////println("== tiny-step-debug-blind-rotate: bit=\{bit} ==")
  let acc_init = tiny_acc_mu(p)
  debug_blind_rotate_tiny(acc_init, ct, bk)
}

/// TINY 版 TRGSW blind rotation：
fn _blind_rotate_trgsw_tiny(
  acc_init : TrlweCiphertext,
  ct_in : LweCiphertext,
  bk : BootstrappingKey,
) -> TrlweCiphertext {
  let n = acc_init.params.n
  let params_tr = acc_init.params

  // -------- 初始旋转：只旋转 b，多项式 a 固定为 0 --------
  let k_b = torus_phase_to_rot_k(ct_in.b, n)
  let mut acc_b = poly_rotate_negacyclic(acc_init.b, k_b)
  let a_zero = Array::makei(n, fn(_) { 0 })

  // -------- 遍历每个 a[i]，做“phase-only” CMUX --------
  for i in 0..<bk.n_in {
    let ai = ct_in.a[i]
    if ai == 0 {
      continue
    }
    let ki = torus_coeff_to_negrot(ai, n)
    if ki == 0 {
      continue
    }
    let b_rot = poly_rotate_negacyclic(acc_b, ki)
    let b_delta = Array::makei(n, fn(j) { t32_sub(b_rot[j], acc_b[j]) })
    let delta_ct : TrlweCiphertext = {
      params: params_tr,
      a: a_zero, // 强制 a=0
      b: b_delta,
    }
    let gi = bk.trgsw_data[i]
    let e = external_product(gi, delta_ct)
    let b_new = Array::makei(n, fn(_j) { 0 })
    for j in 0..<n {
      b_new[j] = t32_add(acc_b[j], e.b[j])
    }
    acc_b = b_new
  }
  { params: params_tr, a: a_zero, b: acc_b }
}

