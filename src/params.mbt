///|
pub struct TfheParams {
  // LWE 参数 
  n_lwe_in : Int
  n_lwe_out : Int
  sigma_lwe : Float
  // KeySwitch 参数
  ks_base_log : Int
  ks_level : Int
  sigma_ks : Float

  // TRLWE 环参数
  n_trlwe : Int // 环多项式维度 n
  sigma_trlwe : Float // TRLWE 噪声
  // BSK（门密钥）参数
  bk_base_log : Int
  bk_level : Int
}

///|
pub suberror ParameterError {
  InvalidDimension
  InvalidPolynomialSize
  DecompositionOverflow
  NegativeNoise
} derive(Debug, Eq)

///|
/// Provenance and intended security metadata for a parameter set.
pub struct TfheParameterMetadata {
  name : String
  security_bits : Int
  failure_exponent : Float
  estimator : String
  noise_distribution : String
  test_only : Bool
}

///|
pub fn tfhe_params_validate(p : TfheParams) -> Result[Unit, ParameterError] {
  if p.n_lwe_in <= 0 || p.n_lwe_out <= 0 || p.n_trlwe <= 0 {
    return Err(InvalidDimension)
  }
  if (p.n_trlwe & (p.n_trlwe - 1)) != 0 {
    return Err(InvalidPolynomialSize)
  }
  if p.ks_base_log <= 0 ||
    p.ks_level <= 0 ||
    p.ks_base_log * p.ks_level < 32 ||
    p.bk_base_log <= 0 ||
    p.bk_level <= 0 ||
    p.bk_base_log * p.bk_level < 32 {
    return Err(DecompositionOverflow)
  }
  if p.sigma_lwe < 0.0 || p.sigma_ks < 0.0 || p.sigma_trlwe < 0.0 {
    return Err(NegativeNoise)
  }
  Ok(())
}

///|
pub fn tfhe_params_metadata(p : TfheParams) -> TfheParameterMetadata {
  if p.n_lwe_in == 805 && p.n_trlwe == 512 {
    {
      name: "tfhe-rs-boolean-default-reference".to_string(),
      security_bits: 132,
      failure_exponent: -64.344,
      estimator: "tfhe-rs 1.7.0 commit 640911e".to_string(),
      noise_distribution: "Gaussian (upstream stddev; not legacy integer sampler)".to_string(),
      test_only: false,
    }
  } else if p.n_lwe_in == 837 && p.n_trlwe == 1024 {
    {
      name: "tfhe-rs-boolean-strong-reference".to_string(),
      security_bits: 165,
      failure_exponent: -165.434,
      estimator: "tfhe-rs 1.7.0 commit 640911e".to_string(),
      noise_distribution: "Gaussian (upstream stddev; not legacy integer sampler)".to_string(),
      test_only: false,
    }
  } else {
    {
      name: "custom-or-toy".to_string(),
      security_bits: 0,
      failure_exponent: 0.0,
      estimator: "not-estimated".to_string(),
      noise_distribution: "bounded integer Gaussian (experimental)".to_string(),
      test_only: true,
    }
  }
}

///|
/// Parameters copied from tfhe-rs Boolean DEFAULT_PARAMETERS dimensions.
/// They are a reference record only until MoonTFHE's Gaussian sampler and
/// estimator reproduce the upstream failure bound.
pub fn tfhe_params_128_reference() -> TfheParams {
  {
    n_lwe_in: 805,
    n_lwe_out: 805,
    sigma_lwe: 0.0000058615896642671336,
    ks_base_log: 8,
    ks_level: 4,
    sigma_ks: 0.0000058615896642671336,
    n_trlwe: 512,
    sigma_trlwe: 0.0000000009315272083503367,
    bk_base_log: 8,
    bk_level: 4,
  }
}

///|
/// Stronger tfhe-rs Boolean reference dimensions (p-fail about 2^-165.434
/// in the upstream estimator). This is not a supported default yet.
pub fn tfhe_params_165_reference() -> TfheParams {
  {
    n_lwe_in: 837,
    n_lwe_out: 837,
    sigma_lwe: 0.000003374714376692653,
    ks_base_log: 8,
    ks_level: 4,
    sigma_ks: 0.000003374714376692653,
    n_trlwe: 1024,
    sigma_trlwe: 0.0000000009313225746198247,
    bk_base_log: 8,
    bk_level: 4,
  }
}

///|
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

///|
/// 用于trgsw单元测试的极小参数
pub fn tfhe_params_tiny_trlwe() -> TfheParams {
  {
    n_lwe_in: 16,
    n_lwe_out: 16,
    sigma_lwe: 0.5,
    ks_base_log: 1,
    ks_level: 2,
    sigma_ks: 0.5,
    n_trlwe: 32, // 关键：32 足够小但结构完整
    sigma_trlwe: 0.5, // 为验证流程调低噪声
    bk_base_log: 1, // base_log=1 → digit 非常稀疏，速度飞快
    bk_level: 2, // 两层 TRGSW，结构完整但小
  }
}

///|
test "params: validation separates toy and reference records" {
  assert_true(tfhe_params_validate(tfhe_params_small_trlwe()) is Ok(_))
  assert_true(tfhe_params_validate(tfhe_params_tiny_trlwe()) is Err(_))
  let reference = tfhe_params_128_reference()
  assert_true(tfhe_params_validate(reference) is Ok(_))
  let metadata = tfhe_params_metadata(reference)
  assert_eq(metadata.security_bits, 132)
  assert_true(!metadata.test_only)
}

///|
/// 计算 B = 2^{base_log}
fn _ks_base(params : TfheParams) -> Int {
  1 << params.ks_base_log
}
