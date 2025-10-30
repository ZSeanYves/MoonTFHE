pub struct TfheParams {
  n_lwe_in  : Int
  n_lwe_out : Int
  sigma_lwe : Float
  ks_base_log : Int
  ks_level    : Int
  sigma_ks    : Float

  // TRLWE 环参数
  n_trlwe : Int          // 环多项式维度 n
  sigma_trlwe : Float    // TRLWE 噪声
  // BSK（门密钥）参数
  bk_base_log : Int
  bk_level    : Int
}

/// 训练用参数
pub fn tfhe_params_small_trlwe() -> TfheParams {
  let a = {
    n_lwe_in: 256,
    n_lwe_out: 256,
    sigma_lwe: 3.0,
    ks_base_log: 4,
    ks_level: 8,
    sigma_ks: 3.0,
    n_trlwe: 512,
    sigma_trlwe: 0.12, //已验证
    bk_base_log: 4,
    bk_level: 8,
  }
  a
}

/// 计算 B = 2^{base_log}
fn _ks_base(params : TfheParams) -> Int {
  1 << params.ks_base_log
}
