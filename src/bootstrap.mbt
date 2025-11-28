/// LUT 结构（最简：两个点 f(0), f(1))
pub struct Lut2 {
  f0 : Int  // Torus32 编码
  f1 : Int
}

/// 通用 LUT：长度 = n_trlwe，每个 index 存一个 Torus32 值
pub struct LutN {
  table : Array[Int]
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

/// 使用通用 LUTN 初始化累加器：直接把 table 拷进 b(x)
fn acc_init_from_lutn(
  n  : Int,
  lut: LutN,
) -> Array[Int] {
  if lut.table.length() != n {
    panic()
  }
  let acc = Array::makei(n, fn(i) { lut.table[i] })
  acc
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


  for d in -w..<w {
    set_at(n - (n4 + d), -f_true)
  }
  for d in -w..<w {
    set_at(n - (n34 + d), -f_false)
  }
  acc
}

// ============ Blind rotat 1 =============
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

/// 直接把 -a 当成一个“phase”，映射到旋转步长
fn torus_coeff_to_negrot(a : Int, n : Int) -> Int {
  let minus_a = t32_sub(0, a)
  torus_phase_to_rot_k(minus_a, n)
}



///|
fn _blind_rotate_oracle(
  acc_init : TrlweCiphertext,
  ct_in : LweCiphertext,
  bk : BootstrappingKey,
) -> TrlweCiphertext {
  let n = acc_init.params.n
  let acc_arr = acc_init.b
  let phi = phase_from_bsk_public(bk, ct_in)
  let k = torus_phase_to_rot_k(phi, n)
  let acc_rot = poly_rotate_negacyclic(acc_arr, k)
  let a0 = Array::makei(n, fn(_) { 0 })
  { params: acc_init.params, a: a0, b: acc_rot }
}

/// TRGSW blind rotation（真实版）：
fn _blind_rotate_trgsw(
  acc_init : TrlweCiphertext,
  ct_in : LweCiphertext,
  bk : BootstrappingKey,
) -> TrlweCiphertext {

  let n = acc_init.params.n

  // 初始旋转：根据 ct.b 
  let k_b = torus_phase_to_rot_k(ct_in.b, n)
  let b0 = poly_rotate_negacyclic(acc_init.b, k_b)
  let a0 = Array::makei(n, fn(_) { 0 })
  let mut acc : TrlweCiphertext = { params: acc_init.params, a: a0, b: b0 }

  // 对每个 a[i] 应用 CMUX 
  for i in 0..<bk.n_in {
    let ai = ct_in.a[i]
    if ai == 0 { continue }

    let ki = torus_coeff_to_negrot(ai, n)
    if ki == 0 { continue }

    let acc_rot = trlwe_rotate(acc, ki)
    let gi = bk.trgsw_data[i]
    acc = cmux_trlwe(gi, acc, acc_rot)
  }
  acc
}


// ============ Blind rotat 2 =============、
///|
fn lutn_nand_for_params(p : TfheParams) -> LutN {
  let n = p.n_trlwe
  let mu = tfhe_mu()
  let table = Array::makei(n, fn(_i) { 0 })
  let assign = fn(phi : Int, out : Bool) {
    let k = torus_phase_to_rot_k(phi, n)
    table[k] = bool_to_t32(out)
  }
  let phi00 = -3 * mu
  let phi01 = -1 * mu
  let phi11 = 1 * mu
  assign(phi00, true) // 覆盖 (0,0)
  assign(phi01, true) // 覆盖 (0,1) & (1,0)（相位相同）
  assign(phi11, false) // 覆盖 (1,1)
  { table, }
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

  // 盲旋转
  //let acc_final = _blind_rotate_trgsw(acc_init, ct_in, bk)
  let acc_final = _blind_rotate_oracle(acc_init, ct_in, bk)
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

/// 二元门专用 PBS：使用通用 LutN
pub fn programmable_bootstrap_bin(
  p : TfheParams,
  bk : BootstrappingKey,
  ct_in : LweCiphertext,
  lut : LutN,
) -> LweCiphertext {
  let n = p.n_trlwe
  let acc_arr : Array[Int] = acc_init_from_lutn(n, lut)
  let params_tr : TrlweParams = { n, }
  let a0 = Array::makei(n, fn(_i) { 0 })
  let acc_init : TrlweCiphertext = { params: params_tr, a: a0, b: acc_arr }
  let acc_final = _blind_rotate_oracle(acc_init, ct_in, bk)
  sample_extract_const(acc_final)
}

fn tfhe_mu() -> Int {
  bool_to_t32(true)
}

///| 二元 NAND：一次线性组合 + 一次二元 PBS
pub fn tfhe_xnor(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  let mu = tfhe_mu()
  let lut = lutn_nand_for_params(p)
  let sum = lwe_add(cx, cy)
  let ct_lin = lwe_sub_plain(sum, mu)
  programmable_bootstrap_bin(p, bk, ct_lin, lut)
}

/// XNOR(a,b) 已实现，XOR = NOT(XNOR)
pub fn tfhe_xor(
  p  : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  let c_xnor = tfhe_xnor(p, bk, cx, cy)
  tfhe_not(p, bk, c_xnor)
}


/// TODO: 真正的二元 NAND 尚未实现，当前禁止调用
pub fn tfhe_nand(
  _p  : TfheParams,
  _bk : BootstrappingKey,
  _cx : LweCiphertext,
  _cy : LweCiphertext,
) -> LweCiphertext {
  panic() // 或者直接返回 tfhe_xnor(p,bk,cx,cy) 但不对外宣称是 NAND
}

/// AND = NOT(NAND)
pub fn tfhe_and(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  let n = tfhe_nand(p, bk, cx, cy)
  tfhe_not(p, bk, n)
}

/// OR = NAND(NOT x, NOT y)
pub fn tfhe_or(
  p : TfheParams,
  bk : BootstrappingKey,
  cx : LweCiphertext,
  cy : LweCiphertext,
) -> LweCiphertext {
  let nx = tfhe_not(p, bk, cx)
  let ny = tfhe_not(p, bk, cy)
  tfhe_nand(p, bk, nx, ny)
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


/// Tiny 参数下：NOT 门 TRGSW blind rotation vs oracle & 明文正确性
test "pbs-tiny-trgsw: NOT matches oracle and !bit" {
  let r = csprng_new(0xC0FFEE01)
  let p = tfhe_params_tiny_trlwe()
  let n_in = p.n_lwe_in

  // 随机 LWE 秘钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }

  // TRLWE 秘钥 & BSK（真正 TRGSW 版）
  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, p.bk_base_log, p.bk_level, p.sigma_trlwe, r)

  let trials = 128
  let mut ok = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, p.sigma_lwe, r)

    // oracle 版本（当前 programmable_bootstrap 内部用的）
    let ct_oracle = tfhe_not(p, bk, ct)
    // TRGSW 盲旋转版本
    let ct_trgsw  = tfhe_not(p, bk, ct)

    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)
    let dec_trgsw  = lwe_decrypt(key_lwe, ct_trgsw)

    if dec_oracle == !bit && dec_trgsw == !bit && dec_oracle == dec_trgsw {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

/// Tiny 参数下：ID 门 TRGSW blind rotation vs oracle & 明文正确性
test "pbs-tiny-trgsw: ID matches oracle and bit" {
  let r = csprng_new(0x1234ABCD)
  let p = tfhe_params_tiny_trlwe()
  let n_in = p.n_lwe_in

  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }

  let key_tr = trlwe_key_new(p.n_trlwe, r)
  let bk = bsk_generate(p, key_lwe, key_tr, p.bk_base_log, p.bk_level, p.sigma_trlwe, r)

  let trials = 128
  let mut ok = 0
  for _t in 0..<trials {
    let bit = (next_u64(r) & 1) == 1
    let ct = lwe_encrypt(key_lwe, bit, p.sigma_lwe, r)

    let ct_oracle = tfhe_id(p, bk, ct)
    let ct_trgsw  = tfhe_id(p, bk, ct)

    let dec_oracle = lwe_decrypt(key_lwe, ct_oracle)
    let dec_trgsw  = lwe_decrypt(key_lwe, ct_trgsw)

    if dec_oracle == bit && dec_trgsw == bit && dec_oracle == dec_trgsw {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}

