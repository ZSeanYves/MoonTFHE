/// BSK V2：每个 LWE 维度对应一个 TRGSW 密文
pub struct BskParamsV2 {
  base_log : Int
  level    : Int
}

pub struct BootstrappingKeyV2 {
  params  : BskParamsV2
  n_in    : Int
  n_trlwe : Int
  data    : Array[TrgswCiphertextV2]  // length = n_in
  s_bits  : Array[Bool]               // 开发态：明文保存 s[i] 用于对照
}

// ========== 小工具 ==========

/// 构造常数多项式：m(X) = mu
fn _const_poly_v2(n : Int, mu : Int) -> Array[Int] {
  let m = Array::makei(n, fn(_i) { 0 })
  if n > 0 {
    m[0] = mu
  }
  m
}
/// 给 V2 blind PBS 用的“大幅度”明文，保证比噪声大很多。
/// sigma=3 左右时，这个量级足够让 b 多项式整体偏向正/负。
const TRGSW_BIG : Int = 1 << 27

/// 使用 TrgswParamsV2 / TrgswCiphertextV2 的“大明文”版本加密：
/// 对给定 bit（= key_lwe.s[i]），生成一条 TRGSW V2：
/// data 长度为 2*level，每一块都是加密了同一个巨大正/负常数多项式。
fn trgsw_encrypt_bit_v2_big(
  params : TrgswParamsV2,
  key_tr : TrlweKey,
  bit : Bool,
  sigma : Float,
  rng : CsPrng,
) -> TrgswCiphertextV2 {
  let n = params.n
  let level = params.level
  let data = Array::makei(2 * level, fn(_idx) {
    let m = Array::makei(n, fn(_i) { 0 })
    let mu = if bit { TRGSW_BIG } else { -TRGSW_BIG }
    m[0] = mu
    trlwe_encrypt(key_tr, m, sigma, rng)
  })
  { params, data }
}

// ========== BSK V2 生成 ==========
///|
pub fn bsk_generate_v2(
  p : TfheParams,
  key_lwe : LweKey,
  key_trlwe : TrlweKey,
  base_log : Int,
  level : Int,
  sigma : Float,
  rng : CsPrng,
) -> BootstrappingKeyV2 {
  let n_in = p.n_lwe_in
  let n = p.n_trlwe
  let bp : BskParamsV2 = { base_log, level }
  let params_trgsw : TrgswParamsV2 = { base_log, level, n }

  // 为每个 LWE 维度 i 生成一个 TRGSW 密文
  let data = Array::makei(n_in, fn(i) {
    let bit = key_lwe.s[i]
    trgsw_encrypt_bit_v2_big(params_trgsw, key_trlwe, bit, sigma, rng)
  })

  // 开发态：保存明文 s[i]，方便和 oracle / V1 对照
  let s_bits = {
    let arr = Array::makei(n_in, fn(_i) { false })
    for i in 0..<n_in {
      arr[i] = key_lwe.s[i]
    }
    arr
  }
  { params: bp, n_in, n_trlwe: n, data, s_bits }
}

// ========== Tests: 结构 & 内容自检 ==========

test "bsk_v2: shape and params" {
  let r = csprng_new(0xB5C0C0DE)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n    = p.n_trlwe

  // 随机 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_i) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(n, r)

  let base_log = 2
  let level    = 3
  let sigma : Float = 3.0

  let bk2 = bsk_generate_v2(p, key_lwe, key_tr, base_log, level, sigma, r)

  assert_eq(bk2.params.base_log, base_log)
  assert_eq(bk2.params.level,    level)
  assert_eq(bk2.n_in,            n_in)
  assert_eq(bk2.n_trlwe,         n)
  assert_eq(bk2.data.length(),   n_in)
  assert_eq(bk2.s_bits.length(), n_in)

  for i in 0..<n_in {
    assert_eq(bk2.s_bits[i], key_lwe.s[i])

    let g = bk2.data[i]
    assert_eq(g.params.base_log, base_log)
    assert_eq(g.params.level,    level)
    assert_eq(g.params.n,        n)
    assert_eq(g.data.length(),   2 * level)

    for j in 0..<g.data.length() {
      assert_eq(g.data[j].params.n, n)
      assert_eq(g.data[j].a.length(), n)
      assert_eq(g.data[j].b.length(), n)
    }
  }
}

test "bsk_v2: first column decrypts back to s[i]" {
  let r = csprng_new(0xA11CE)
  let p = tfhe_params_small_trlwe()
  let n_in = p.n_lwe_in
  let n    = p.n_trlwe

  // 随机 LWE/TRLWE 秘钥
  let s = Array::makei(n_in, fn(_i) { false })
  for i in 0..<n_in {
    s[i] = (next_u64(r) & 1) == 1
  }
  let key_lwe : LweKey = { s, }
  let key_tr  = trlwe_key_new(n, r)

  let base_log = 2
  let level    = 3
  let sigma : Float = 3.0

  let bk2 = bsk_generate_v2(p, key_lwe, key_tr, base_log, level, sigma, r)

  // 抽查若干 i，逐层检查 data[2*l] 是否解回 s[i]
  let checks = if n_in < 8 { n_in } else { 8 }
  let mut ok = 0
  for i in 0..<checks {
    let g = bk2.data[i]
    for l in 0..<level {
      let ct0 = g.data[2 * l]      // Enc(s[i] * g_l)
      let bit_dec = trlwe_decrypt_bit0(key_tr, ct0)
      if bit_dec == key_lwe.s[i] {
        ok = ok + 1
      }
    }
  }
  assert_eq(ok, checks * level)
}
