///|
/// Compatibility alias for the ChaCha20 generator owned by `src/random`.
pub type CsPrng = @random.RandomGenerator

///|
/// Deterministic generator reserved for tests and reproducible fixtures.
/// Production callers must use `SecureRng` instead.
pub type TestRng = CsPrng

///|
pub fn test_rng_new(seed : UInt64) -> TestRng {
  @random.test_rng_new(seed)
}

///|
/// 用 64 位种子初始化
fn csprng_new(seed : UInt64) -> CsPrng {
  @random.test_rng_new(seed)
}

///|
/// 产生下一个 u64（就地更新 rng.val.state）
fn next_u64(rng : CsPrng) -> UInt64 {
  rng.next_u64()
}

///|
/// 产生下一个 u32（低 32 位）
fn next_u32(rng : CsPrng) -> Int {
  rng.next_u32().reinterpret_as_int()
}

///|
/// 均匀浮点 in [0,1)
fn next_f64_01(rng : CsPrng) -> Float {
  let mantissa = rng.next_u64() >> 11
  Float::from_double(mantissa.to_double() / 9007199254740992.0)
}
