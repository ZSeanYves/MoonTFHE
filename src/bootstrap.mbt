// ============ Tool =============

///|
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

///|
///测试用
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

///|
fn[T] _slice(arr : Array[T], start : Int, end : Int) -> Array[T] {
  let res = Array::makei(end - start, fn(_) { arr[start] }) // 占位初始
  for i in start..<end {
    res[i - start] = arr[i]
  }
  res
}

// ============ Bootstrap =============

// ============ Blind rotat 1 =============

///|
/// TRLWE 旋转：同时对 a(X), b(X) 做 negacyclic 旋转
fn trlwe_rotate(ct : TrlweCiphertext, k : Int) -> TrlweCiphertext {
  let params = ct.params
  let a2 = poly_rotate_negacyclic(ct.a, k)
  let b2 = poly_rotate_negacyclic(ct.b, k)
  { params, a: a2, b: b2 }
}

///|
/// CMUX(s, c0, c1) = c0 + s·(c1 - c0)，其中 s 由 TRGSW(g) 加密
fn cmux_trlwe(
  g : TrgswCiphertext,
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

///|
/// 直接把 -a 当成一个“phase”，映射到旋转步长
fn torus_coeff_to_negrot(a : Int, n : Int) -> Int {
  let minus_a = t32_sub(0, a)
  torus_phase_to_rot_k(minus_a, n)
}

///|
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
    if ai == 0 {
      continue
    }

    let ki = torus_coeff_to_negrot(ai, n)
    if ki == 0 {
      continue
    }

    let acc_rot = trlwe_rotate(acc, ki)
    let gi = bk.trgsw_data[i]
    acc = cmux_trlwe(gi, acc, acc_rot)
  }
  acc
}

///|
/// Build the two-point Boolean test vector used by the unary PBS path. With
/// the symmetric encoding, the coefficient at X^(N/2) produces opposite
/// phases for rotations +N/2 and -N/2.
fn accumulator_set_output(
  polynomial : Array[Int],
  rotation : Int,
  output : Int,
) -> Unit {
  let n = polynomial.length()
  let period = 2 * n
  let exponent = (period - rotation % period) % period
  if exponent < n {
    polynomial[exponent] = output
  } else {
    polynomial[exponent - n] = -output
  }
}

///|
fn boolean_accumulator(
  n : Int,
  _input_mu : Int,
  f_true : Int,
  f_false : Int,
) -> TrlweCiphertext {
  if n <= 0 || (n & (n - 1)) != 0 || f_false != -f_true {
    panic()
  }
  let b = Array::make(n, 0)
  // Rotations [0, N) represent non-negative torus phases. The negacyclic
  // relation supplies the opposite output automatically for [N, 2N).
  for rotation in 0..<n {
    accumulator_set_output(b, rotation, f_true)
  }
  { params: { n, }, a: Array::make(n, 0), b }
}

///|
fn programmable_bootstrap_accumulator(
  p : TfheParams,
  bk : BootstrappingKey,
  ciphertext : LweCiphertext,
  accumulator : TrlweCiphertext,
) -> LweCiphertext {
  let rotated = _blind_rotate_trgsw(accumulator, ciphertext, bk)
  let extracted = sample_extract_const(rotated)
  ksk_apply(p, bk.key_switch, extracted)
}

///|
/// Secret-free programmable bootstrap for a symmetric unary Boolean LUT.
/// The result is key-switched back to the client LWE key recorded in the
/// encrypted evaluation key.
pub fn programmable_bootstrap(
  p : TfheParams,
  bk : BootstrappingKey,
  ciphertext : LweCiphertext,
  f_true : Int,
  f_false : Int,
) -> LweCiphertext {
  let accumulator = boolean_accumulator(p.n_trlwe, T32_EIGHTH, f_true, f_false)
  programmable_bootstrap_accumulator(p, bk, ciphertext, accumulator)
}

///|
pub fn tfhe_id(
  p : TfheParams,
  bk : BootstrappingKey,
  ciphertext : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, ciphertext, T32_EIGHTH, -T32_EIGHTH)
}

///|
pub fn tfhe_not(
  p : TfheParams,
  bk : BootstrappingKey,
  ciphertext : LweCiphertext,
) -> LweCiphertext {
  programmable_bootstrap(p, bk, ciphertext, -T32_EIGHTH, T32_EIGHTH)
}

///|
/// NAND for ciphertexts encoded with `T32_EIGHTH`.
pub fn tfhe_nand(
  p : TfheParams,
  bk : BootstrappingKey,
  left : LweCiphertext,
  right : LweCiphertext,
) -> LweCiphertext {
  let combined = lwe_sub_plain(lwe_add(left, right), T32_EIGHTH)
  let n = p.n_trlwe
  let polynomial = Array::make(n, 0)
  // Mixed inputs are centered at rotation 0 and evaluate to true. Two true
  // inputs are centered at N/2 and evaluate to false. The anti-periodic half
  // then maps two false inputs (3N/2) back to true.
  let false_start = n / 8
  let false_end = 3 * n / 8
  let false_start_2 = 5 * n / 8
  let false_end_2 = 7 * n / 8
  for rotation in 0..<n {
    let in_first_false = rotation >= false_start && rotation < false_end
    let in_second_false = rotation >= false_start_2 && rotation < false_end_2
    let output = if in_first_false || in_second_false {
      -T32_EIGHTH
    } else {
      T32_EIGHTH
    }
    accumulator_set_output(polynomial, rotation, output)
  }
  let accumulator : TrlweCiphertext = {
    params: { n, },
    a: Array::make(n, 0),
    b: polynomial,
  }
  programmable_bootstrap_accumulator(p, bk, combined, accumulator)
}

///|
pub fn tfhe_and(
  p : TfheParams,
  bk : BootstrappingKey,
  left : LweCiphertext,
  right : LweCiphertext,
) -> LweCiphertext {
  tfhe_not(p, bk, tfhe_nand(p, bk, left, right))
}

///|
pub fn tfhe_or(
  p : TfheParams,
  bk : BootstrappingKey,
  left : LweCiphertext,
  right : LweCiphertext,
) -> LweCiphertext {
  let not_left = tfhe_not(p, bk, left)
  let not_right = tfhe_not(p, bk, right)
  tfhe_nand(p, bk, not_left, not_right)
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
