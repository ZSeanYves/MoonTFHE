// 轻量可复现的伪随机数（SplitMix64）
///|TODO:后续可替换为系统熵或更强 DRBG。
pub struct CsPrng {
  mut state : UInt64
}

/// 用 64 位种子初始化
fn csprng_new(seed : UInt64) -> CsPrng {
  let s = seed ^ 0x9E37_79B9_7F4A_7C15
  let a = { state: s }
  a
}

/// SplitMix64 步进
fn splitmix64_step(x : UInt64) -> UInt64 {
  let mut z = x + 0x9E37_79B9_7F4A_7C15
  z = (z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9
  z = (z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB
  z ^ (z >> 31)
}

/// 产生下一个 u64（就地更新 rng.val.state）
fn next_u64(rng : CsPrng) -> UInt64 {
  let z = splitmix64_step(rng.state)
  rng.state = z
  z
}

/// 产生下一个 u32（低 32 位）
fn next_u32(rng : CsPrng) -> Int {
  (next_u64(rng) & 0xFFFF_FFFF).to_int()
}

/// 均匀浮点 in [0,1)
fn next_f64_01(rng : CsPrng) -> Float {
  // 取 53 位有效随机数 / 2^53
  let v = next_u64(rng) >> 11 // 保留高 53 位
  v.to_float() / 9007199254740992.0 // 2^53
}
