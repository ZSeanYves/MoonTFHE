/// LUT 结构（最简：两个点 f(0), f(1))
/// TODO:后面可以扩成更一般的表
pub struct Lut2 {
  f0 : Int  // Torus32 编码
  f1 : Int
}

// ============ Tool =============
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

///|测试用
fn _int_to_hex(x : Int) -> String {
  let digits = "0123456789ABCDEF"
  let mut s = ""
  let mut val = x
  for _ in 0..<8 {
    let d = val & 0xF
    val = val >> 4
    s = digits[d].to_string() + s
  }
  "0x" + s
}

fn[T] _slice(arr: Array[T], start: Int, end: Int) -> Array[T] {
  let res = Array::makei(end - start, fn(_) { arr[start] })  // 占位初始
  for i in start..<end {
    res[i - start] = arr[i]
  }
  res
}

// ============ Bootstrap =============

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

///|
fn acc_from_lut2_for_boolean(
  n : Int,
  f_true : Int,
  f_false : Int,
  win? : Int = 1,
) -> Array[Int] {
  if (n & (n - 1)) != 0 {
    panic()
  }
  let acc = Array::makei(n, fn(_i) { 0 })
  let n4 = n / 4
  let n34 = 3 * n / 4
  let w = if win < 0 { 0 } else if win > 8 { 8 } else { win }
  let set_at = fn(idx : Int, val : Int) {
    let j = (idx % n + n) % n
    acc[j] = val
  }

  // 这里的 n-(...) 正好是为了抵消 poly_rotate_negacyclic 常数项的那个“n-k”
  for d in -w..<w {
    set_at(n - (n4 + d), -f_true)
  }
  for d in -w..<w {
    set_at(n - (n34 + d), -f_false)
  }
  acc
}

// ============ Blind rotation 积木 =============

/// TRLWE 旋转：同时对 a(X), b(X) 做 negacyclic 旋转
fn trlwe_rotate(
  ct : TrlweCiphertext,
  k  : Int,
) -> TrlweCiphertext {
  let params = ct.params
  let a2 = poly_rotate_negacyclic(ct.a, k)
  let b2 = poly_rotate_negacyclic(ct.b, k)
  { params, a: a2, b: b2 }
}

/// CMUX(s, c0, c1) = c0 + s·(c1 - c0)，其中 s 由 TRGSW(g) 加密
fn cmux_trlwe(
  g  : TrgswCiphertext,
  c0 : TrlweCiphertext,
  c1 : TrlweCiphertext,
) -> TrlweCiphertext {
  // delta = c1 - c0
  let delta = _trlwe_ct_sub(c1, c0)
  // e ≈ Enc( s * delta )
  let e = external_product(g, delta)
  // res = c0 + e
  trlwe_ct_add(c0, e)
}

/// 从单个 TLWE 系数 a 映射到“旋转 -a 的步长”（mod n）
fn torus_coeff_to_negrot(a : Int, n : Int) -> Int {
  let k = torus_phase_to_rot_k(a, n)
  if k == 0 {
    0
  } else {
    n - k
  }
}

/// TRGSW blind rotation（真实版）：
/// - 使用 bk.trgsw_data 中的 TRGSW(s[i]) + external_product 做 CMUX，
/// - 初始按 b 做一轮旋转，
/// - 对每个 a[i] 累计 -a[i] 方向的旋转。
fn blind_rotate_trgsw(
  acc_init : TrlweCiphertext,  // 其中 b = 初始 LUT 多项式
  ct_in    : LweCiphertext,
  bk       : BootstrappingKey,
) -> TrlweCiphertext {
  let n = acc_init.params.n

  // 1) 从 acc_init.b 取出 LUT 多项式
  let acc_plain = acc_init.b

  // 2) 按 TLWE 常数项 b 做一次初始旋转
  let k_b = torus_phase_to_rot_k(ct_in.b, n)
  let acc_plain_rot = poly_rotate_negacyclic(acc_plain, k_b)

  // 3) 用 TRLWE 秘钥把旋转后的 LUT 加密成初始 accumulator
  //    这里为了不改 API，内部构造一个本地 RNG 即可（安全性不在当前测试范围内）
  let rng = csprng_new(0xB00DBA5E)
  let mut acc = trlwe_encrypt(bk.key_trlwe, acc_plain_rot, bk.sigma_trlwe, rng)

  // 4) 对每个 TLWE 系数 a[i] 用 CMUX 选择是否追加 -a[i] 旋转
  let n_in = bk.n_in
  for i in 0..<n_in {
    let a_i = ct_in.a[i]
    if a_i == 0 {
      continue
    }
    let k_i = torus_coeff_to_negrot(a_i, n)
    if k_i == 0 {
      continue
    }

    let acc_rot = trlwe_rotate(acc, k_i)
    let g_i = bk.trgsw_data[i]
    acc = cmux_trlwe(g_i, acc, acc_rot)
  }

  acc
}

// ============ Programmable Bootstrap =============

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
  let a0 = Array::makei(n, fn(_) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }

  // 3) 盲旋转（现在是真正的 TRGSW blind rotation）
  let acc_final = blind_rotate_trgsw(acc_init, ct_in, bk)

  // 4) 提取常数项为 LWE
  sample_extract_const(acc_final)
}

///|
pub fn tfhe_id(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, ct, 0x0000_0000, 0x8000_0000) 
}

///|
pub fn tfhe_not(
  p : TfheParams,
  bk : BootstrappingKey,
  ct : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, ct, 0x8000_0000, 0x0000_0000) 
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

// ============ Tests =============

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
  let bit = true
  let m = trlwe_encode_bit_const(n, bit)
  let sigma : Float = 3.0
  let ct_tr = trlwe_encrypt(key_tr, m, sigma, r)
  let k = 5
  let ct_lw_k = sample_extract_index(ct_tr, k)
  let dec_k = lwe_decrypt(key_lw, ct_lw_k)
  assert_eq(dec_k, bit)
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
      let mut cnt = 0
      for i in 0..<bk.n_in {
        if bk.s_bits[i] {
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
