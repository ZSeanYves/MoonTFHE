// ========== TRGSW V2 & BSK V2：结构定义 ==========

pub struct TrgswParamsV2 {
  base_log : Int
  level    : Int
  n        : Int        // = TRLWE n
}

/// 经典形状（k=1 简化版）：2 * level 个 TRLWE
pub struct TrgswCiphertextV2 {
  params : TrgswParamsV2
  data   : Array[TrlweCiphertext]   // length = 2 * level
}



// ========== TRGSW V2 生成：表示一个比特 s_i = 0/1 ==========

/// 用 TRLWE 秘钥 key_tr 加密一个比特 bit，生成 TrgswCiphertextV2
/// data[2*l]   ≈ Enc( s * g_l )
/// data[2*l+1] ≈ Enc(     g_l )
fn _trgsw_encrypt_bit_v2(
  params : TrgswParamsV2,
  key_tr : TrlweKey,
  bit : Bool,
  sigma : Float,
  rng : CsPrng,
) -> TrgswCiphertextV2 {
  let n = params.n
  let level = params.level
  let data : Array[TrlweCiphertext] = Array::makei(2 * level, fn(_i) {
    let p_tr : TrlweParams = { n, }
    let a = Array::makei(n, fn(_j) { 0 })
    let b = Array::makei(n, fn(_j) { 0 })
    { params: p_tr, a, b }
  })
  for l in 0..<level {
    // 振幅：沿用你现在 BSK 的思路，再整体缩小一截避免过激
    // T32_QUARTER >> (l+3) 大约是 0.25 / 2^{l+3}
    let amp_l = T32_QUARTER >> (l + 3)

    // Enc( s * g_l ) ：用对称编码 ±amp_l
    let m0 = _const_poly_v2(n, t32_encode_bit_pm(bit, amp_l))
    let ct0 = trlwe_encrypt(key_tr, m0, sigma, rng)

    // Enc( g_l ) ：恒为 +amp_l，只在更完整的 TRGSW 运算时会用到
    let m1 = _const_poly_v2(n, amp_l)
    let ct1 = trlwe_encrypt(key_tr, m1, sigma, rng)
    data[2 * l] = ct0
    data[2 * l + 1] = ct1
  }
  { params, data }
}

