///|
pub struct BskParams {
  base_log : Int
  level    : Int
}

///
/// 新版 BootstrappingKey：
/// - 不再存扁平 TRLWE 矩阵
/// - 直接存每个 LWE 秘钥位对应的 TRGSW(s[i])
/// - 额外带上 TRLWE 秘钥和 PBS 用的 sigma，方便 blind rotation 使用
///|
pub struct BootstrappingKey {
  params       : BskParams        // base_log, level
  n_in         : Int              // LWE 输入维度
  n_trlwe      : Int              // TRLWE 多项式长度 n
  trgsw_params : TrgswParams      // base_log, level, n
  trgsw_data   : Array[TrgswCiphertext] // 长度 = n_in，每个是 TRGSW(s[i])
  s_bits       : Array[Bool]      // Dev-only：公开 s[i]，方便无密钥 PBS 测试
  key_trlwe    : TrlweKey         // TRLWE 秘钥（给 PBS 里的 acc 加密用）
  sigma_trlwe  : Float            // PBS 中使用的 TRLWE 噪声
}

///|线性下标计算（扁平 data 时的工具）
fn _bsk_idx(l : Int, i : Int, n_in : Int) -> Int {
  l * n_in + i
}

/// 将 BootstrappingKey 转成 TRGSW 数组：
/// 现在已经是直接存的 trgsw_data，不需要再从扁平 TRLWE 里拼
///|
fn _bsk_to_trgsw_array(bk : BootstrappingKey) -> Array[TrgswCiphertext] {
  bk.trgsw_data
}

/// 仍保留 phase_from_bsk_public，方便和之前 fake PBS 做对比用：
/// 利用公开的 s_bits 直接计算 φ = b - <a, s>
///|
fn _phase_from_bsk_public(bk : BootstrappingKey, ct : LweCiphertext) -> Int {
  let n = bk.n_in
  let mut dot = 0
  for i in 0..<n {
    if bk.s_bits[i] {
      dot = t32_add(dot, ct.a[i])
    }
  }
  t32_sub(ct.b, dot)
}


/// 生成 BootstrappingKey：
/// - 对每个 LWE 秘钥位 s[i] 生成一个 TRGSW(s[i])，存入 trgsw_data[i]
/// - 同时保存 s_bits、TRLWE 秘钥 key_trlwe 以及 PBS 用的 sigma
///|
pub fn bsk_generate(
  p : TfheParams,
  key_lwe : LweKey,
  key_trlwe : TrlweKey,
  base_log : Int,
  level : Int,
  sigma_bsk : Float,
  rng : CsPrng,
) -> BootstrappingKey {
  let bp : BskParams = { base_log, level }
  let n_in = p.n_lwe_in
  let n_tr = p.n_trlwe

  // TRGSW 参数：环维度 n_tr，base_log / level 来自调用参数
  let trgsw_params : TrgswParams = { base_log, level, n: n_tr }

  // s_bits：公开版本的 LWE 秘钥比特（Dev-only）
  let s_bits = {
    let arr = Array::makei(n_in, fn(_) { false })
    for i in 0..<n_in {
      arr[i] = key_lwe.s[i]
    }
    arr
  }

  // 为每个 LWE 秘钥位 s[i] 生成 TRGSW(s[i])
  let trgsw_data : Array[TrgswCiphertext] = Array::makei(n_in, fn(i) {
    let bit = key_lwe.s[i]
    trgsw_encrypt_bool(trgsw_params, key_trlwe, bit, sigma_bsk, rng)
  })

  // PBS 中 accumulator 用的 TRLWE 噪声，先用和 sigma_bsk 相同
  let sigma_trlwe : Float = sigma_bsk
  {
    params: bp,
    n_in,
    n_trlwe: n_tr,
    trgsw_params,
    trgsw_data,
    s_bits,
    key_trlwe,
    sigma_trlwe,
  }
}


///|
test "bsk: trgsw shape matches (n_in, level, n_trlwe)" {
  let r = csprng_new(0xB5C0CB)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n = p.n_trlwe

  // 构造 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr = trlwe_key_new(n, r)
  let base_log = 2
  let level = 3
  let sigma : Float = 3.0
  let bk = bsk_generate(p, key_lwe, key_tr, base_log, level, sigma, r)

  // BSK 顶层参数检查
  assert_eq(bk.params.base_log, base_log)
  assert_eq(bk.params.level, level)
  assert_eq(bk.n_in, n_in)
  assert_eq(bk.n_trlwe, n)
  assert_eq(bk.trgsw_params.base_log, base_log)
  assert_eq(bk.trgsw_params.level, level)
  assert_eq(bk.trgsw_params.n, n)

  // trgsw_data 长度应为 n_in
  assert_eq(bk.trgsw_data.length(), n_in)

  // 每个 TRGSW 应该有 2 * level 行，每行是 TRLWE(n)
  for i in 0..<n_in {
    let g = bk.trgsw_data[i]
    assert_eq(g.params.base_log, base_log)
    assert_eq(g.params.level, level)
    assert_eq(g.params.n, n)
    assert_eq(g.data.length(), 2 * level)
    for row in 0..<g.data.length() {
      let ct = g.data[row]
      assert_eq(ct.params.n, n)
      assert_eq(ct.a.length(), n)
      assert_eq(ct.b.length(), n)
    }
  }
}
