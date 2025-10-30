pub struct TrgswParams {
  base_log : Int
  level    : Int
  n        : Int         // = TRLWE n
}

// TRGSW 按分解层存多份 TRLWE（典型实现是 2*level 份）
///|
pub struct TrgswCiphertext {
  params : TrgswParams
  // 先用 level 份；后续按需要扩成 2*level 等
  data : Array[TrlweCiphertext]
}

// 先做“空密文”：加密 0（占位）——方便 blind_rotate 的接口接通
///|
pub fn trgsw_encrypt_zero(
  params : TrgswParams,
  _rng : CsPrng,
) -> TrgswCiphertext {
  let n = params.n
  let dummy = Array::makei(n, fn(_) { 0 })
  let shell : TrlweCiphertext = { params: { n, }, a: dummy, b: dummy }
  let arr = Array::makei(params.level, fn(_) { shell })
  { params, data: arr }
}
