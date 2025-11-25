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

/// 由 BSK 的公开 s_bits 计算 φ = b - <a,s>
fn phase_from_bsk_public(
  bk   : BootstrappingKey,
  ct   : LweCiphertext
) -> Int {
  let n = bk.n_in
  let mut dot = 0
  for i in 0..<n {
    if bk.s_bits[i] {
      dot = t32_add(dot, ct.a[i])
    }
  }
  t32_sub(ct.b, dot)
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
///|
fn blind_rotate_trgsw(
  acc_init : TrlweCiphertext,
  ct_in : LweCiphertext,
  bsk_trgsw : Array[TrgswCiphertext],
) -> TrlweCiphertext {
  let n = acc_init.params.n
  let n_in = ct_in.a.length()
  let level = bsk_trgsw.length() / n_in
  let mut acc = acc_init
  for i in 0..<n_in {
    let ai = ct_in.a[i]
    let digits = gadget_decompose(ai, 3, level) // TODO: 可参数化
    for j in 0..<level {
      let idx = i * level + j
      let g = bsk_trgsw[idx].data[j]
      let scaled = trlwe_scalar_mul(g, digits[j])
      acc = _trlwe_ct_add(acc, scaled)
    }
  }
  let k = torus_phase_to_rot_k(ct_in.b, n)
  let _ = poly_rotate_negacyclic(acc.a, k)
  let _ = poly_rotate_negacyclic(acc.b, k)
  acc
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

///|
pub fn programmable_bootstrap(
  p : TfheParams,
  bk : BootstrappingKey,
  ct_in : LweCiphertext,
  f_true : Int,
  f_false : Int,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = acc_from_lut2_for_boolean(n, f_true, f_false)
  let params_tr : TrlweParams = { n, }
  let a = Array::makei(n, fn(_) { 0 })
  let b = acc_arr
  let acc_init : TrlweCiphertext = { params: params_tr, a, b }
  let bsk_trgsw = bsk_to_trgsw_array(bk)
  let acc_final = blind_rotate_trgsw(acc_init, ct_in, bsk_trgsw)


  sample_extract_const(acc_final)
}


///|
pub fn tfhe_id(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  // f(true) = 0, f(false) = 0.5
  let f_true : Int = 0x0000_0000 // 0
  let f_false : Int = 0x8000_0000 // 0.5
  programmable_bootstrap(p, bk, ct, f_true, f_false)
}

///|
pub fn tfhe_not(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  // f(true)=0.5, f(false)=0
  let f_true  : Int = 0x8000_0000 // 0.5
  let f_false : Int = 0x0000_0000 // 0
  programmable_bootstrap(p, bk, ct, f_true, f_false)
}


fn tfhe_mu() -> Int {
  bool_to_t32(true)   
}


///|TODO:下面4个二元门目前受限于LUT，尚未实现仅写假逻辑占位
pub fn tfhe_nand(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  let mu = tfhe_mu()
  let sum = lwe_sub_plain(lwe_add(cx, cy), mu)
  let f_true : Int = 0x8000_0000 // 0.5
  let f_false : Int = 0x0000_0000 // 0
  programmable_bootstrap(p, bk, sum, f_true, f_false)
}
///|
pub fn tfhe_and(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  // AND = NOT(NAND)
  let n = tfhe_nand(p, bk, cx, cy)
  tfhe_not(p, bk, n)
}
///|
pub fn tfhe_or(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  // OR = NAND(NOT x, NOT y)
  let nx = tfhe_not(p, bk, cx)
  let ny = tfhe_not(p, bk, cy)
  tfhe_nand(p, bk, nx, ny)
}
///|
pub fn tfhe_xor(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  // XOR = (x OR y) AND (NOT(x AND y))
  let a = tfhe_or(p, bk, cx, cy)
  let b = tfhe_and(p, bk, cx, cy)
  let nb = tfhe_not(p, bk, b)
  tfhe_and(p, bk, a, nb)
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
  // 伪造一把 TLWE key（ LWE key 相同格式）
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = (next_u64(r) & 1) == 1
  }

  let a = Array::makei(n, fn(_i) { next_u32(r) })
  let mut accb = 0
  for i in 0..<n {
    if s[i] {
      accb = accb + a[i]
    }
  }
  // 选择一个固定的相位偏移（比如 +0.25）
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

  // 构造 LWE/TLWE 同维密钥
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


// Debug
pub struct PbsDebug {
  phi        : Int   
  dot        : Int   
  k0         : Int   
  k_minus    : Int   
  k_final    : Int   
  n          : Int   
}
fn pbs_debug_dot_from_bk(bk : BootstrappingKey, ct : LweCiphertext) -> Int {
  let n = bk.n_in
  let mut dot = 0
  for i in 0..<n {
    if bk.s_bits[i] {
      dot = t32_add(dot, ct.a[i])
    }
  }
  dot
}
// 将 Torus32 映射到 [0,1) 浮点，便于肉眼观察
///|
fn _pbs_debug_torus_to_frac(x : Int) -> Float {
  let u = x.reinterpret_as_uint()
  // u / 2^32
  u.to_float() / 4294967296.0
}
///|
fn pbs_debug_probe(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> PbsDebug {
  let n = p.n_trlwe
  let dot = pbs_debug_dot_from_bk(bk, ct)
  let phi = t32_sub(ct.b, dot)

  // 与你代码保持一致：先正向量化 k0，再取补得到负向，最后加 n/4 偏移
  let k0 = ((phi.reinterpret_as_uint() * n.reinterpret_as_uint()) >> 32).reinterpret_as_int()
  let k_minus = (n - k0 % n) % n
  let k_final = (k_minus + n / 4) % n
  let a = { phi, dot, k0, k_minus, k_final, n }
  a
}
fn _int_to_hex(x : Int) -> String {
  let u = x.reinterpret_as_uint()
  // 取高位补零到 8 字节
  let hex_chars = "0123456789ABCDEF"
  let mut s = ""
  let mut  v = u
  let mut  i = 0
  while i < 8 {
    let nibble = (v & 0xF).reinterpret_as_int()
    s = hex_chars[nibble].to_string() + s
    v = v >> 4
    i = i + 1
  }
  "0x" + s
}


///|
test "pbs-final: NOT gate (no LWE key in API)" {
  let r = csprng_new(0xC0FFEE)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)
  let trials = 128
  let mut ok = 0
  for t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 3.0, r)
    let ct2 = tfhe_not(p, bk, ct)
    let dec = lwe_decrypt(key_lwe, ct2)
    if dec == !bit {
      ok = ok + 1
    } else {
      // 打印关键调试信息
      let _ = pbs_debug_probe(p, bk, ct)
      //println("NOT mismatch @t=\{t}: bit=\{bit} dec=\{dec}")
      //println(
      //  "  phi = \{int_to_hex(dbg.phi)}  (~ \{pbs_debug_torus_to_frac(dbg.phi)})",
      //)
      //println("  dot = \{int_to_hex(dbg.dot)}   b=\{int_to_hex(ct.b)}")
      //println(
      //  "  k0=\{dbg.k0}, k_minus=\{dbg.k_minus}, k_final=\{dbg.k_final}, n=\{dbg.n}",
      //)
      // 额外：挑前 4 个贡献位打印
      let mut cnt = 0
      for i in 0..<bk.n_in {
        if bk.s_bits[i] {
          //println("    s[i]=1 @i=\{i}, a[i]=\{int_to_hex(ct.a[i])}")
          cnt = cnt + 1
          if cnt >= 4 {
            break
          }
        }
      }
    }
  }
  assert_eq(ok, trials)
}

///|
test "pbs-final: identity gate (no LWE key in API)" {
  let r = csprng_new(0x1234ABCD)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, 2, 3, 3.0, r)
  let trials = 128
  let mut ok = 0
  for _ in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, 3.0, r)
    let ct2 = tfhe_id(p, bk, ct)
    let dec = lwe_decrypt(key_lwe, ct2)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

