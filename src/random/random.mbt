///|
pub suberror RandomError {
  UnsupportedBackend
  EntropyUnavailable
  InvalidDistribution
} derive(Debug, Eq)

///|
/// ChaCha20-based deterministic random generator. Production instances are
/// seeded from the host entropy provider; test instances are explicitly
/// constructed from a reproducible seed.
pub struct RandomGenerator {
  key : Array[UInt]
  mut counter : UInt
  block : Array[UInt]
  mut block_index : Int
  secure_seeded : Bool
}

///|
fn rotate_left(value : UInt, count : Int) -> UInt {
  (value << count) | (value >> (32 - count))
}

///|
fn quarter_round(
  state : Array[UInt],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
) -> Unit {
  state[a] = state[a] + state[b]
  state[d] = rotate_left(state[d] ^ state[a], 16)
  state[c] = state[c] + state[d]
  state[b] = rotate_left(state[b] ^ state[c], 12)
  state[a] = state[a] + state[b]
  state[d] = rotate_left(state[d] ^ state[a], 8)
  state[c] = state[c] + state[d]
  state[b] = rotate_left(state[b] ^ state[c], 7)
}

///|
fn RandomGenerator::refill(self : RandomGenerator) -> Unit {
  let initial : Array[UInt] = [
    0x61707865U,
    0x3320646eU,
    0x79622d32U,
    0x6b206574U,
    self.key[0],
    self.key[1],
    self.key[2],
    self.key[3],
    self.key[4],
    self.key[5],
    self.key[6],
    self.key[7],
    self.counter,
    0U,
    0U,
    0U,
  ]
  let state = initial.copy()
  for _ in 0..<10 {
    quarter_round(state, 0, 4, 8, 12)
    quarter_round(state, 1, 5, 9, 13)
    quarter_round(state, 2, 6, 10, 14)
    quarter_round(state, 3, 7, 11, 15)
    quarter_round(state, 0, 5, 10, 15)
    quarter_round(state, 1, 6, 11, 12)
    quarter_round(state, 2, 7, 8, 13)
    quarter_round(state, 3, 4, 9, 14)
  }
  for i in 0..<16 {
    self.block[i] = state[i] + initial[i]
  }
  self.counter = self.counter + 1U
  self.block_index = 0
}

///|
fn random_generator_from_key(
  key : Array[UInt],
  secure_seeded : Bool,
) -> RandomGenerator {
  {
    key,
    counter: 0U,
    block: Array::make(16, 0U),
    block_index: 16,
    secure_seeded,
  }
}

///|
/// Reproducible generator reserved for tests and fixtures.
pub fn test_rng_new(seed : UInt64) -> RandomGenerator {
  let low = seed.to_uint()
  let high = (seed >> 32).to_uint()
  let key = Array::makei(8, fn(i) {
    let lane = (i + 1).reinterpret_as_uint()
    low ^ rotate_left(high + lane * 0x9E3779B9U, (i * 5 + 7) % 31 + 1)
  })
  random_generator_from_key(key, false)
}

///|
/// Create a production generator from the host entropy provider.
pub fn secure_rng_new() -> Result[RandomGenerator, RandomError] {
  if !entropy_backend_available() {
    return Err(UnsupportedBackend)
  }
  let key = Array::makei(8, fn(_) { entropy_backend_u32() })
  let mut nonzero = false
  for word in key {
    if word != 0U {
      nonzero = true
    }
  }
  if !nonzero {
    return Err(EntropyUnavailable)
  }
  Ok(random_generator_from_key(key, true))
}

///|
pub fn RandomGenerator::is_secure(self : RandomGenerator) -> Bool {
  self.secure_seeded
}

///|
pub fn RandomGenerator::next_u32(self : RandomGenerator) -> UInt {
  if self.block_index >= 16 {
    self.refill()
  }
  let value = self.block[self.block_index]
  self.block_index = self.block_index + 1
  value
}

///|
pub fn RandomGenerator::next_u64(self : RandomGenerator) -> UInt64 {
  self.next_u32().to_uint64() | (self.next_u32().to_uint64() << 32)
}

///|
pub fn RandomGenerator::uniform_01(self : RandomGenerator) -> Double {
  let mantissa = self.next_u64() >> 11
  mantissa.to_double() / 9007199254740992.0
}

///|
/// Discrete Gaussian sampled by bounded rejection over [-ceil(8 sigma), +ceil(8 sigma)].
/// The sampler exposes its finite 8-sigma support to parameter validation.
pub fn RandomGenerator::sample_discrete_gaussian(
  self : RandomGenerator,
  sigma : Double,
) -> Result[Int, RandomError] {
  if sigma < 0.0 || sigma != sigma {
    return Err(InvalidDistribution)
  }
  if sigma == 0.0 {
    return Ok(0)
  }
  let bound = (8.0 * sigma).ceil().to_int().max(1)
  let width = 2 * bound + 1
  for ;; {
    let candidate = (self.next_u32().reinterpret_as_int() & 0x7FFF_FFFF) % width -
      bound
    let exponent = -Double::from_int(candidate * candidate) /
      (2.0 * sigma * sigma)
    if self.uniform_01() <= @math.exp(exponent) {
      return Ok(candidate)
    }
  }
}

///|
test "random: deterministic ChaCha stream is reproducible" {
  let left = test_rng_new(0x434841434841)
  let right = test_rng_new(0x434841434841)
  for _ in 0..<64 {
    assert_eq(left.next_u64(), right.next_u64())
  }
  assert_true(!left.is_secure())
}

///|
test "random: discrete Gaussian is bounded and non-degenerate" {
  let rng = test_rng_new(0x4741555353)
  let mut nonzero = 0
  for _ in 0..<1000 {
    let sample = rng.sample_discrete_gaussian(3.0).unwrap()
    assert_true(sample >= -24 && sample <= 24)
    if sample != 0 {
      nonzero = nonzero + 1
    }
  }
  assert_true(nonzero > 0)
}
