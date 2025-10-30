/// LUT 结构（最简：两个点 f(0), f(1))
/// TODO:后面可以扩成更一般的表
pub struct Lut2 {
  f0 : Int  // Torus32 编码
  f1 : Int
}

// TOOLS
/// 要求 n 是 2 的幂，返回 log2(n)；否则 panic
fn log2_pow2(n : Int) -> Int {
  let mut x = n
  let mut lg = 0
  if n <= 0 {
    panic()
  }
  if (x & (x - 1)) != 0 {
    panic()
  } // 非 2 的幂
  while x > 1 {
    x = x >> 1
    lg = lg + 1
  }
  lg
}
/// 把 TLWE 相位（torus 32 位）映射到环 Z[X]/(X^n+1) 的“旋转步数”k：
fn torus_phase_to_rot_k(t : Int, n : Int) -> Int {
  let l = log2_pow2(n)
  let shift = 32 - l
  // 以无符号视角右移，得到 [0, n) 的整步
  let ku = (t.reinterpret_as_uint() >> shift) & (n.reinterpret_as_uint() - 1)
  ku.reinterpret_as_int()
}
/// 计算 TLWE 相位 phi = b - <a, s>  
fn tlwe_phase(a : Array[Int], b : Int, s : Array[Bool]) -> Int {
  let n = a.length()
  let mut acc = 0
  for i in 0..<n {
    if s[i] {
      acc = acc + a[i]
    }
  }
  b - acc
}
/// 对 k ≈ n/4（输入 true）在 pos = n - (n/4 + d) 处放置 -f_true
/// 对 k ≈ 3n/4（输入 false）在 pos = n - (3n/4 + d) 处放置 -f_false
/// 其中 d ∈ [-win, +win].  
/// 旋转后若落到 0 位并发生一次折返，则得到 +f，实现容差。
fn acc_from_lut2_for_boolean(
  n : Int,
  f_true : Int,
  f_false : Int,
  win? : Int = 1, //PS:win建议 1
) -> Array[Int] {
  if (n & (n - 1)) != 0 {
    panic()
  } // n 必须为 2 的幂
  let acc = Array::makei(n, fn(_i) { 0 })
  let n4 = n / 4
  let n34 = 3 * n / 4

  // clamp 窗口，避免过大
  let w = if win < 0 { 0 } else if win > 8 { 8 } else { win }
  let set_at = fn(idx : Int, val : Int) {
    let j = (idx % n + n) % n
    acc[j] = val
  }

  // k ≈ n/4 → 目标值应为 f_true，预置在 3n/4 - d（取反）
  for d in -w..<w {
    set_at(n - (n4 + d), -f_true)
  }
  // k ≈ 3n/4 → 目标值应为 f_false，预置在 n/4 - d（取反）
  for d in -w..<w {
    set_at(n - (n34 + d), -f_false)
  }
  acc
}
///|外积（占位）：acc ⊗ ggsw -> acc'  (TODO: 用真 TRGSW 内容实现)
pub fn external_product(
  _acc : TrlweCiphertext,
  _ggsw : TrgswCiphertext,
) -> TrlweCiphertext {
  // 占位：目前直接返回 _acc，不改变（为不破坏现有编译/测试）
  _acc
}






/// 构造布尔 LUT（常见：NAND/AND/XOR 等），这里仅提供一个构造器
fn _lut2_from_bools(y0 : Bool, y1 : Bool) -> Lut2 {
  // y0 = f(0), y1 = f(1)
  let v0 = bool_to_t32(y0) // 0 or 0.5
  let v1 = bool_to_t32(y1)
  let a = { f0: v0, f1: v1 }
  a
}

/// 初始化累加器多项式：把 v 放在常数项（index 0），其它为 0
fn acc_init_const(n : Int, v : Int) -> Array[Int] {
  let a = Array::makei(n, fn(_i) { 0 })
  a[0] = v
  a
}

/// 针对布尔函数的“可编程累加器”: 按位选择 f0 或 f1 的常数项
/// PS：这里并不根据密文选择，仅构建两个候选。实际选择由盲旋转完成。
fn _acc_init_for_lut(n : Int, lut : Lut2) -> (Array[Int], Array[Int]) {
  let acc0 = acc_init_const(n, lut.f0)
  let acc1 = acc_init_const(n, lut.f1)
  (acc0, acc1)
}



/// 盲旋转,返回：按相位对应的“负循环旋转”后的累加器
fn blind_rotate_oracle(
  acc : Array[Int],
  ct : LweCiphertext,
  s : Array[Bool],
) -> Array[Int] {
  let n = acc.length()
  let phi = tlwe_phase(ct.a, ct.b, s)
  let k = torus_phase_to_rot_k(phi, n)
  // 负循环旋转：与 poly_rotate_negacyclic 方向一致（X^n = -1）
  poly_rotate_negacyclic(acc, k)
}
///|TRGSW 版盲旋转（骨架）：acc ← acc ⊗ Π_i GGSW(a_i)，以及根据 b 做常数旋转
fn _blind_rotate_trgsw(
  acc_init : TrlweCiphertext,
  _ct_in : LweCiphertext,
  _bsk_trgsw : Array[TrgswCiphertext], // 预期形状：level*n_in 或 2*level*n_in
) -> TrlweCiphertext {
  // TODO: 这里实现：
  // 1) a_i 的基-B 分解
  // 2) 依次对 acc 应用 external_product(acc, BSK[i][ell])，相当于旋转
  // 3) 用 b 的分解做常数旋转
  // 现在先返回 acc_init，保持占位不影响编译和现有测试
  acc_init
}

/// 从 TRLWE 提取为 LWE：提取第 k 个系数
fn sample_extract_index(ct : TrlweCiphertext, k : Int) -> LweCiphertext {
  let n = ct.a.length()
  if k < 0 || k >= n {
    panic()
  }

  // a' 向量
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    let t = k - i
    if t >= 0 {
      a[i] = ct.a[t]
    } else {
      // 折返取反：X^n = -1
      a[i] = -ct.a[t + n]
    }
  }
  // b' = b[k]
  let b = ct.b[k]
  let s = { a, b }
  s
}

/// 将 TRLWE 的 {0,1} 多项式密钥转换为同维度 LWE 密钥（逐系数）
fn lwe_key_from_trlwe_key(k_tr : TrlweKey) -> LweKey {
  let n = k_tr.params.n
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = k_tr.s[i]
  }
  let a = { s, }
  a
}

/// 专门提取常数项（k = 0），做一个便捷封装
fn sample_extract_const(ct : TrlweCiphertext) -> LweCiphertext {
  sample_extract_index(ct, 0)
}

/// 流程：累加器构造 -> 盲旋转（oracle）-> 提取常数项为 LWE
fn programmable_bootstrap_oracle(
  p : TfheParams,
  key : LweKey,
  ct : LweCiphertext,
  f0 : Int,
  f1 : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc = acc_from_lut2_for_boolean(n, f0, f1)
  let acc_rot = blind_rotate_oracle(acc, ct, key.s)
  let ct_ring : TrlweCiphertext = {
    let params : TrlweParams = { n, }
    let a : Array[Int] = Array::makei(n, fn(_i) { 0 })
    let b : Array[Int] = acc_rot
    { params, a, b }
  }
  sample_extract_const(ct_ring)
}

///|正式 API：签名稳定，内部暂时调用 ref 版（oracle），避免上层改动
pub fn programmable_bootstrap(
  p : TfheParams,
  bk : BootstrappingKey, // 结构沿用你当前 BSK
  key : LweKey, // 先保留，用 ref 版。实现 TRGSW 后会删掉这个参数
  ct : LweCiphertext,
  f_true : Int,
  f_false : Int,
) -> LweCiphertext {
  // TODO：当 blind_rotate_trgsw 实现完成后，替换为真自举：
  // 1) acc = acc_from_lut2_quarter_window(…)
  // 2) acc' = blind_rotate_trgsw(acc, ct, bk_trgsw)
  // 3) return sample_extract_const(acc')
  programmable_bootstrap_ref(p, bk, key, ct, f_true, f_false)
}

///|TODO:同名能力，但“临时”要求传 key，用 oracle 跑通逻辑链路。实现 blind rotation 后一行替换。
fn programmable_bootstrap_ref(
  p : TfheParams,
  _bk : BootstrappingKey, // 形参保留，当前不使用
  key : LweKey,           // 明文 oracle 需要真密钥
  ct : LweCiphertext,
  f_true : Int,
  f_false : Int,
) -> LweCiphertext {
  programmable_bootstrap_oracle(p, key, ct, f_true, f_false)
}

///|// 便捷门（正式 API，内部依旧走 ref）
pub fn tfhe_not(
  p : TfheParams,
  bk : BootstrappingKey,
  key : LweKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, key, ct, bool_to_t32(false), bool_to_t32(true))
}
///|
pub fn tfhe_id(
  p : TfheParams,
  bk : BootstrappingKey,
  key : LweKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, key, ct, bool_to_t32(true), bool_to_t32(false))
}

/// PBS：NOT 门
fn pbs_oracle_not(
  p : TfheParams,
  key : LweKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  // 逻辑函数 f(x): NOT
  let f_true = bool_to_t32(false) // 输入 true → 输出 false
  let f_false = bool_to_t32(true) // 输入 false → 输出 true

  // 构造累加器 (k≈n/4 对应 true, k≈3n/4 对应 false)
  let acc = acc_from_lut2_for_boolean(p.n_trlwe, f_true, f_false)
  let acc_rot = blind_rotate_oracle(acc, ct, key.s)
  let ct_ring : TrlweCiphertext = {
    let params : TrlweParams = { n: p.n_trlwe }
    let a : Array[Int] = Array::makei(p.n_trlwe, fn(_) { 0 })
    let b : Array[Int] = acc_rot
    { params, a, b }
  }
  sample_extract_const(ct_ring)
}

/// PBS：恒等门 (identity)
fn pbs_oracle_id(
  p : TfheParams,
  key : LweKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  // 逻辑函数 f(x): IDENTITY
  let f_true = bool_to_t32(true) // 输入 true → 输出 true
  let f_false = bool_to_t32(false) // 输入 false → 输出 false
  let acc = acc_from_lut2_for_boolean(p.n_trlwe, f_true, f_false)
  let acc_rot = blind_rotate_oracle(acc, ct, key.s)
  let ct_ring : TrlweCiphertext = {
    let params : TrlweParams = { n: p.n_trlwe }
    let a : Array[Int] = Array::makei(p.n_trlwe, fn(_) { 0 })
    let b : Array[Int] = acc_rot
    { params, a, b }
  }
  sample_extract_const(ct_ring)
}




///|
test "sample_extract: TRLWE const -> LWE decrypt equals plaintext bit (k=0)" {
  let r = csprng_new(0x53554D45)
  let n = 512
  let key_tr = trlwe_key_new(n, r)
  let key_lw = lwe_key_from_trlwe_key(key_tr)
  let trials = 128
  let sigma : Float = 3.0
  let mut ok = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let m = trlwe_encode_bit_const(n, bit)
    let ct_tr = trlwe_encrypt(key_tr, m, sigma, r)

    // 提取常数项为 LWE
    let ct_lw = sample_extract_const(ct_tr)
    let dec = lwe_decrypt(key_lw, ct_lw)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

///|
test "sample_extract: TRLWE const at k>0 rotates as expected (roundtrip via manual rotate)" {
  let r = csprng_new(0xABCD1234)
  let n = 16
  let key_tr = trlwe_key_new(n, r)
  let key_lw = lwe_key_from_trlwe_key(key_tr)

  // 固定 bit，验证 k != 0 的抽取索引规则
  let bit = true
  let m = trlwe_encode_bit_const(n, bit)
  let sigma : Float = 3.0
  let ct_tr = trlwe_encrypt(key_tr, m, sigma, r)

  // 抽取 k = 5
  let k = 5
  let ct_lw_k = sample_extract_index(ct_tr, k)
  let dec_k = lwe_decrypt(key_lw, ct_lw_k)
  assert_eq(dec_k, bit)
}


/// 构造一个“可见旋转”的累加器：仅在 idx=1 放值，其余为 0
fn make_probe_acc(n : Int, val : Int) -> Array[Int] {
  let acc = Array::makei(n, fn(_i) { 0 })
  if n > 1 {
    acc[1] = val
  }
  acc
}

/// 用真相位计算旋转步数，再直接调用 poly_rotate_negacyclic，
/// 与 oracle 的结果逐项相等
test "blind-rotate-oracle: rotation matches explicit negacyclic rotation" {
  let r = csprng_new(0xB10F)
  let n = 512
  // 伪造一把 TLWE key（与项目里 LWE key 相同格式）
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (next_u64(r) & 1) == 1
  }

  // 构造随机 TLWE (a,b) —— 这里不需要是“真实加密”，只要 (a,b) 给出一个相位就行
  let a = Array::makei(n, fn(_i) { next_u32(r) })
  let mut accb = 0
  for i in 0..<n {
    if s[i] {
      accb = accb + a[i]
    }
  }
  // 选择一个固定的相位偏移（比如 +0.25），这样旋转步数稳定可见
  let mu = T32_QUARTER
  let b = accb + mu
  let ct = { a, b }

  // 让累加器只有 idx=1 一个非零点，旋转后的目标索引应为 (1 + k) mod n 或带折返号位的等效点
  let acc0 = make_probe_acc(n, 123456789)
  let acc_oracle = blind_rotate_oracle(acc0, ct, s)

  // 直接由相位→k 手工旋转
  let phi = b - accb // = mu
  let k = torus_phase_to_rot_k(phi, n)
  let acc_ref = poly_rotate_negacyclic(acc0, k)

  // 逐项相等
  let len = acc_ref.length()
  for i in 0..<len {
    assert_eq(acc_oracle[i], acc_ref[i])
  }
}

/// 用真实的 TLWE 加密产生命文，检查 oracle 盲旋转结果与显式旋转一致
test "blind-rotate-oracle: with real TLWE encryption (phase-driven)" {
  let r = csprng_new(0xC0FFEE)
  let n = 512

  // 构造 LWE/TLWE 同维密钥（项目里已有 LWE key 生成器也可以拿来用）
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key = { s, }

  // 真加密一比特到 TLWE（常数项 ±0.25），以保证相位与门限语义一致
  let sigma : Float = 3.0
  let bit = (next_u64(r) & 1) == 1
  let ct = lwe_encrypt(key, bit, sigma, r)

  // 探针累加器
  let acc0 = make_probe_acc(n, 777)

  // oracle 旋转
  let acc_oracle = blind_rotate_oracle(acc0, ct, key.s)

  // 直接由相位推 k 的参考实现
  // phi = b - <a,s>
  let mut acca = 0
  for i in 0..<n {
    if key.s[i] {
      acca = acca + ct.a[i]
    }
  }
  let phi = ct.b - acca
  let k = torus_phase_to_rot_k(phi, n)
  let acc_ref = poly_rotate_negacyclic(acc0, k)

  // 逐项比较
  let len = acc_ref.length()
  for i in 0..<len {
    assert_eq(acc_oracle[i], acc_ref[i])
  }
}

///|
test "pbs-oracle: NOT gate on random bits" {
  let r = csprng_new(0xDEADBEEF)
  let p = tfhe_params_small_trlwe()

  // TLWE key（与 p.n_lwe_in 同维）
  let n = p.n_lwe_in
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key : LweKey = { s, }
  let trials = 128
  let sigma : Float = 3.0
  let mut ok = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key, bit, sigma, r)
    ///调试用
    ///let phi = (ct.b - (fn () {
    ///  let mut acc = 0
    ///  for i in 0..<n { if key.s[i] { acc = acc + ct.a[i] } }
    ///  acc
    ///})())
    ///let k = torus_phase_to_rot_k(phi, p.n_trlwe)
    ///println("k = \{k}")  // bit=false → k应≈ n/2；bit=true → k=0
    let ct2 = pbs_oracle_not(p, key, ct)
    let dec = lwe_decrypt(key, ct2)
    if dec == !bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

///|
test "pbs-oracle: identity (no-op) preserves bit" {
  let r = csprng_new(0x12345678)
  let p = tfhe_params_small_trlwe()
  let n = p.n_lwe_in
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key : LweKey = { s, }
  let trials = 128
  let sigma : Float = 3.0
  let mut ok = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key, bit, sigma, r)
    let ct2 = pbs_oracle_id(p, key, ct)
    let dec = lwe_decrypt(key, ct2)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

///|
test "tfhe_not_ref: homomorphic NOT (via oracle ref pipeline)" {
  let r = csprng_new(0xC0FFEE)
  let p = tfhe_params_small_trlwe()

  // LWE/TRWE key
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)

  // BSK（目前内容没用上，但结构/接口已对齐）
  let bk = bsk_generate(p, key, key_tr, 2, 3, 3.0, r)
  let trials = 128
  let mut ok = 0
  for _ in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key, bit, 3.0, r)
    let ct2 = tfhe_not(p, bk, key, ct)
    let dec = lwe_decrypt(key, ct2)
    if dec == !bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

///|
test "tfhe_id_ref: homomorphic identity (via oracle ref pipeline)" {
  let r = csprng_new(0x1234ABCD)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key, key_tr, 2, 3, 3.0, r)
  let trials = 128
  let mut ok = 0
  for _ in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key, bit, 3.0, r)
    let ct2 = tfhe_id(p, bk, key, ct)
    let dec = lwe_decrypt(key, ct2)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}
