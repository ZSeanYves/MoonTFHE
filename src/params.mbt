// 统一参数（先覆盖 LWE & KSK）
///|
pub struct TfheParams {
  n_lwe_in : Int        // 输入 LWE 维度
  n_lwe_out : Int       // 输出 LWE 维度
  sigma_lwe : Float     // LWE 加密噪声
  // Key Switching 分解参数
  ks_base_log : Int     // B = 2^{base_log}
  ks_level : Int        // t 个层级
  sigma_ks : Float
} // KSK 中用于加密的噪声

/// 一个安全、训练用的小参数（跑测快）
fn tfhe_params_small() -> TfheParams {
  let a = {
    n_lwe_in: 256,
    n_lwe_out: 256,
    sigma_lwe: 3.0, // Torus 上几个 LSB
    ks_base_log: 4, // B=16
    ks_level: 8,    // 覆盖 32 位
    sigma_ks: 3.0,
  }
  a
}

/// 计算 B = 2^{base_log}
fn ks_base(params : TfheParams) -> Int {
  1 << params.ks_base_log
}
