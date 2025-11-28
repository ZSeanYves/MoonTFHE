pub struct TfheParams {
  // LWE 参数 
  n_lwe_in  : Int
  n_lwe_out : Int
  sigma_lwe : Float
  // KeySwitch 参数
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

/// 正常训练用参数
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


/// 用于trgsw单元测试的极小参数
pub fn tfhe_params_tiny_trlwe() -> TfheParams {
  {
    n_lwe_in: 16,
    n_lwe_out: 16,
    sigma_lwe: 0.5,

    ks_base_log: 1,
    ks_level: 2,
    sigma_ks: 0.5,

    n_trlwe: 32,          // 关键：32 足够小但结构完整
    sigma_trlwe: 0.5,     // 为验证流程调低噪声

    bk_base_log: 1,       // base_log=1 → digit 非常稀疏，速度飞快
    bk_level: 2,          // 两层 TRGSW，结构完整但小
  }
}


/// 计算 B = 2^{base_log}
fn _ks_base(params : TfheParams) -> Int {
  1 << params.ks_base_log
}
