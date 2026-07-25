///|
pub suberror RandomError {
  UnsupportedBackend
  EntropyUnavailable
  InvalidEntropyLength
  InvalidDistribution
} derive(Debug, Eq)

///|
/// A host-provided entropy callback. The callback must return exactly `count`
/// bytes or `None` when the host cannot satisfy the request.
pub type EntropyProvider = (Int) -> Bytes?

///|
pub enum RandomDomain {
  KeyGeneration
  EncryptionMask
  EncryptionNoise
  BootstrapKey
  SerializationNonce
} derive(Debug, Eq)

///|
let entropy_provider : Ref[EntropyProvider?] = @ref.new(None)

///|
pub fn install_entropy_provider(provider : EntropyProvider) -> Unit {
  entropy_provider.val = Some(provider)
}

///|
pub fn clear_entropy_provider() -> Unit {
  entropy_provider.val = None
}

///|
fn read_entropy(count : Int) -> Result[Bytes, RandomError] {
  if count < 0 {
    return Err(InvalidEntropyLength)
  }
  match entropy_provider.val {
    Some(provider) =>
      match provider(count) {
        Some(bytes) =>
          if bytes.length() == count {
            Ok(bytes)
          } else {
            Err(InvalidEntropyLength)
          }
        None => Err(EntropyUnavailable)
      }
    None =>
      match entropy_backend_bytes(count) {
        Some(bytes) => Ok(bytes)
        None => Err(UnsupportedBackend)
      }
  }
}

///|
/// ChaCha20-based deterministic random generator. Production instances are
/// seeded from the host entropy provider; test instances are explicitly
/// constructed from a reproducible seed.
pub struct RandomGenerator {
  key : Array[UInt]
  mut counter : UInt
  nonce : Array[UInt]
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
    self.nonce[0],
    self.nonce[1],
    self.nonce[2],
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
  nonce : Array[UInt],
  secure_seeded : Bool,
) -> RandomGenerator {
  {
    key,
    counter: 0U,
    nonce,
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
  // Preserve the historical fixture stream for deprecated compatibility
  // tests. Production streams are domain-separated in `secure_rng_new_for`.
  let nonce = [0U, 0U, 0U]
  random_generator_from_key(key, nonce, false)
}

///|
/// Create a production generator from the host entropy provider.
pub fn secure_rng_new() -> Result[RandomGenerator, RandomError] {
  secure_rng_new_for(EncryptionMask)
}

///|
pub fn secure_encryption_mask_rng_new() -> Result[RandomGenerator, RandomError] {
  secure_rng_new_for(EncryptionMask)
}

///|
pub fn secure_encryption_noise_rng_new() -> Result[RandomGenerator, RandomError] {
  secure_rng_new_for(EncryptionNoise)
}

///|
/// Return the domain reserved for serialization nonces without exposing enum
/// constructor details to facade packages.
pub fn serialization_nonce_domain() -> RandomDomain {
  SerializationNonce
}

///|
pub fn key_generation_domain() -> RandomDomain {
  KeyGeneration
}

///|
pub fn bootstrap_key_domain() -> RandomDomain {
  BootstrapKey
}

///|
/// Create a production stream separated by a protocol-owned domain label.
pub fn secure_rng_new_for(
  domain : RandomDomain,
) -> Result[RandomGenerator, RandomError] {
  let seed = match read_entropy(44) {
    Ok(bytes) => bytes
    Err(error) => return Err(error)
  }
  let key = Array::makei(8, fn(i) { load_u32_le(seed, i * 4) })
  let nonce = Array::makei(3, fn(i) { load_u32_le(seed, 32 + i * 4) })
  nonce[0] = nonce[0] ^ domain.tag()
  Ok(random_generator_from_key(key, nonce, true))
}

///|
fn RandomDomain::tag(self : RandomDomain) -> UInt {
  match self {
    KeyGeneration => 0x4B455947U
    EncryptionMask => 0x454D4153U
    EncryptionNoise => 0x454E4F49U
    BootstrapKey => 0x42534B59U
    SerializationNonce => 0x534E4F4EU
  }
}

///|
fn load_u32_le(bytes : Bytes, offset : Int) -> UInt {
  bytes[offset].to_uint() |
  (bytes[offset + 1].to_uint() << 8) |
  (bytes[offset + 2].to_uint() << 16) |
  (bytes[offset + 3].to_uint() << 24)
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
/// Versioned 128-bit fixed-point cumulative distribution table. Each chunk
/// stores `(high, low)` UInt64 words for at most 4096 thresholds.
pub struct DiscreteGaussian {
  sigma_q32 : UInt64
  tail_bound : Int
  cdt_length : Int
  cdt_chunks : Array[FixedArray[UInt64]]
  fixture_hash : String
}

///|
/// The small sigma=3 fixture is used by toy key generation during C1. Standard
/// parameter tables are introduced together with their estimator records.
pub fn gaussian_sigma_3_fixture() -> DiscreteGaussian {
  {
    sigma_q32: 3UL << 32,
    tail_bound: 24,
    cdt_length: 25,
    cdt_chunks: [
      FixedArray::from_array([
        0x220B06EFC59DC000UL, 0UL, 0x627326E31B016000UL, 0UL, 0x98F80C58C41FC000UL,
        0UL, 0xC243E9165D940800UL, 0UL, 0xDE419EB854B03800UL, 0UL, 0xEF3BD7AEDFB2A800UL,
        0UL, 0xF872BE6BD7C64800UL, 0UL, 0xFCEC65493DA1D000UL, 0UL, 0xFEDE4B3B6D0EB000UL,
        0UL, 0xFF9FEC9E1608F000UL, 0UL, 0xFFE34EB751D53800UL, 0UL, 0xFFF84A73D0751000UL,
        0UL, 0xFFFE2351715FF000UL, 0UL, 0xFFFF98909E326000UL, 0UL, 0xFFFFEBD8F78A6000UL,
        0UL, 0xFFFFFC79E8784000UL, 0UL, 0xFFFFFF727D757000UL, 0UL, 0xFFFFFFEC177B8800UL,
        0UL, 0xFFFFFFFD7D26D800UL, 0UL, 0xFFFFFFFFB7517000UL, 0UL, 0xFFFFFFFFF8A2B800UL,
        0UL, 0xFFFFFFFFFF54D800UL, 0UL, 0xFFFFFFFFFFF21800UL, 0UL, 0xFFFFFFFFFFFF0000UL,
        0UL, 0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL,
      ]),
    ],
    fixture_hash: "test-only:sigma-3-u128-expanded-u64".to_string(),
  }
}

///|
/// Deterministic zero-noise distribution reserved for structural tests. It is
/// never selected by production parameter records or `generate_keys`.
pub fn test_zero_noise_fixture() -> DiscreteGaussian {
  {
    sigma_q32: 0UL,
    tail_bound: 0,
    cdt_length: 1,
    cdt_chunks: [
      FixedArray::from_array([0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL]),
    ],
    fixture_hash: "test-only:zero-noise".to_string(),
  }
}

///|
pub fn DiscreteGaussian::sigma_q32(self : DiscreteGaussian) -> UInt64 {
  self.sigma_q32
}

///|
pub fn DiscreteGaussian::tail_bound(self : DiscreteGaussian) -> Int {
  self.tail_bound
}

///|
pub fn DiscreteGaussian::fixture_hash(self : DiscreteGaussian) -> String {
  self.fixture_hash
}

///|
pub fn RandomGenerator::sample_discrete_gaussian_fixed(
  self : RandomGenerator,
  distribution : DiscreteGaussian,
) -> Result[Int, RandomError] {
  if distribution.cdt_length <= 0 || distribution.cdt_chunks.length() == 0 {
    return Err(InvalidDistribution)
  }
  let draw_high = self.next_u64()
  let draw_low = self.next_u64()
  let mut low = 0
  let mut high = distribution.cdt_length - 1
  while low < high {
    let middle = (low + high) / 2
    let (threshold_high, threshold_low) = distribution.cdt_threshold(middle)
    if draw_high < threshold_high ||
      (draw_high == threshold_high && draw_low <= threshold_low) {
      high = middle
    } else {
      low = middle + 1
    }
  }
  let magnitude = low
  if magnitude == 0 || (self.next_u32() & 1U) == 0U {
    Ok(magnitude)
  } else {
    Ok(-magnitude)
  }
}

///|
fn DiscreteGaussian::cdt_threshold(
  self : DiscreteGaussian,
  index : Int,
) -> (UInt64, UInt64) {
  let chunk_index = index / 4096
  let word_index = index % 4096 * 2
  let chunk = self.cdt_chunks[chunk_index]
  (chunk[word_index], chunk[word_index + 1])
}

///|
/// Decode a generated hexadecimal CDT chunk. Whitespace is ignored so each
/// chunk remains a single compiler constant instead of thousands of AST nodes.
fn cdt_chunk_from_hex(encoded : String) -> FixedArray[UInt64] {
  let words : Array[UInt64] = []
  let mut value = 0UL
  let mut digits = 0
  for character in encoded {
    let code = character.to_int()
    let nibble = if code >= '0'.to_int() && code <= '9'.to_int() {
      code - '0'.to_int()
    } else if code >= 'A'.to_int() && code <= 'F'.to_int() {
      code - 'A'.to_int() + 10
    } else if code >= 'a'.to_int() && code <= 'f'.to_int() {
      code - 'a'.to_int() + 10
    } else {
      -1
    }
    if nibble >= 0 {
      value = (value << 4) | nibble.to_uint64()
      digits = digits + 1
      if digits == 16 {
        words.push(value)
        value = 0UL
        digits = 0
      }
    }
  }
  if digits != 0 || words.length() == 0 || words.length() % 2 != 0 {
    abort("invalid generated CDT chunk")
  }
  FixedArray::from_array(words)
}

///|
pub fn RandomGenerator::sample_tuniform(
  self : RandomGenerator,
  bound : Int,
) -> Result[Int, RandomError] {
  if bound <= 0 || bound > 0x3FFF_FFFF {
    return Err(InvalidDistribution)
  }
  let width = 2 * bound + 1
  let draw = (self.next_u32() & 0x7FFF_FFFFU).reinterpret_as_int()
  Ok(draw % width - bound)
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
test "random: RFC 8439 ChaCha20 block vector" {
  let key = Array::makei(8, fn(i) {
    let base = (i * 4).reinterpret_as_uint()
    base | ((base + 1U) << 8) | ((base + 2U) << 16) | ((base + 3U) << 24)
  })
  let nonce = [0x09000000U, 0x4A000000U, 0U]
  let rng = random_generator_from_key(key, nonce, false)
  rng.counter = 1U
  let expected = [
    0xE4E7F110U, 0x15593BD1U, 0x1FDD0F50U, 0xC47120A3U, 0xC7F4D1C7U, 0x0368C033U,
    0x9AAA2204U, 0x4E6CD4C3U, 0x466482D2U, 0x09AA9F07U, 0x05D7C214U, 0xA2028BD9U,
    0xD19C12B5U, 0xB94E16DEU, 0xE883D0CBU, 0x4E3C50A2U,
  ]
  for word in expected {
    assert_eq(rng.next_u32(), word)
  }
}

///|
test "random: fixed-point CDT has stable moments and support" {
  let rng = test_rng_new(0x434454464958)
  let distribution = gaussian_sigma_3_fixture()
  let mut sum = 0
  let mut squared_sum = 0
  for _ in 0..<20000 {
    let sample = rng.sample_discrete_gaussian_fixed(distribution).unwrap()
    assert_true(sample >= -24 && sample <= 24)
    sum = sum + sample
    squared_sum = squared_sum + sample * sample
  }
  assert_true(sum > -1000 && sum < 1000)
  assert_true(squared_sum > 150000 && squared_sum < 210000)
}

///|
test "random: fixed-point CDT known vector" {
  let rng = test_rng_new(0x434454464958)
  let distribution = gaussian_sigma_3_fixture()
  let actual : Array[Int] = []
  for _ in 0..<20 {
    actual.push(rng.sample_discrete_gaussian_fixed(distribution).unwrap())
  }
  inspect(
    actual,
    content=(
      #|[-2, -1, 2, 2, 1, 4, -2, 0, -1, -2, -4, -3, -2, 1, -1, 0, 1, -2, 6, 2]
    ),
  )
}

///|
test "random: standard Boolean CDT fixtures are bounded and reproducible" {
  let low = gaussian_boolean_110_glwe_fixture()
  let high = gaussian_boolean_128_lwe_fixture()
  assert_eq(low.tail_bound(), 33)
  assert_eq(high.tail_bound(), 115955)
  assert_true(low.fixture_hash().has_prefix("sha256:"))
  assert_true(high.fixture_hash().has_prefix("sha256:"))
  let rng = test_rng_new(0x5354414E44415244)
  for _ in 0..<128 {
    let low_sample = rng.sample_discrete_gaussian_fixed(low).unwrap()
    assert_true(low_sample >= -33 && low_sample <= 33)
    let high_sample = rng.sample_discrete_gaussian_fixed(high).unwrap()
    assert_true(high_sample >= -115955 && high_sample <= 115955)
  }
}

///|
test "random: standard Boolean LWE CDT moments match quantized sigma" {
  let cases = [
    (gaussian_boolean_110_lwe_fixture(), 550000000L, 720000000L),
    (gaussian_boolean_128_lwe_fixture(), 180000000L, 250000000L),
  ]
  for case_index in 0..<cases.length() {
    let (distribution, variance_low, variance_high) = cases[case_index]
    let rng = test_rng_new(0x5354415449535449UL + case_index.to_uint64())
    let mut sum = 0L
    let mut squared_sum = 0L
    for _ in 0..<20000 {
      let sample = rng.sample_discrete_gaussian_fixed(distribution).unwrap()
      let wide = sample.to_int64()
      sum = sum + wide
      squared_sum = squared_sum + wide * wide
    }
    let variance = squared_sum / 20000L
    assert_true(sum > -10000000L && sum < 10000000L)
    assert_true(variance > variance_low && variance < variance_high)
  }
}

///|
test "random: standard Boolean CDT fixed seed vector" {
  let rng = test_rng_new(0x5354444344543132UL)
  let actual : Array[Int] = []
  let low = gaussian_boolean_110_lwe_fixture()
  let high = gaussian_boolean_128_lwe_fixture()
  for _ in 0..<8 {
    actual.push(rng.sample_discrete_gaussian_fixed(low).unwrap())
    actual.push(rng.sample_discrete_gaussian_fixed(high).unwrap())
  }
  inspect(
    actual,
    content=(
      #|[-13990, -707, -7071, 10383, 21037, 13329, 12329, -24850, -30481, 21487, 6973, -2831, 32075, -66, -6573, 6127]
    ),
  )
}

///|
test "random: entropy provider validates output and separates domains" {
  install_entropy_provider(fn(count) { Some(Bytes::make(count - 1, 0)) })
  assert_true(secure_rng_new() is Err(InvalidEntropyLength))
  install_entropy_provider(fn(count) { Some(Bytes::make(count, 0xA5)) })
  let keygen = secure_rng_new_for(KeyGeneration).unwrap()
  let mask = secure_rng_new_for(EncryptionMask).unwrap()
  assert_true(keygen.is_secure())
  assert_true(mask.is_secure())
  assert_true(keygen.next_u32() != mask.next_u32())
  clear_entropy_provider()
}
