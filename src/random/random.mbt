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
  priv key : SecretWords
  priv mut counter : UInt
  priv nonce : SecretWords
  priv block : SecretWords
  priv mut block_index : Int
  priv secure_seeded : Bool
  priv mut destroyed : Bool
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
    secret_words_get(self.key, 0),
    secret_words_get(self.key, 1),
    secret_words_get(self.key, 2),
    secret_words_get(self.key, 3),
    secret_words_get(self.key, 4),
    secret_words_get(self.key, 5),
    secret_words_get(self.key, 6),
    secret_words_get(self.key, 7),
    self.counter,
    secret_words_get(self.nonce, 0),
    secret_words_get(self.nonce, 1),
    secret_words_get(self.nonce, 2),
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
    secret_words_set(self.block, i, state[i] + initial[i])
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
    key: secret_words_from_array(key),
    counter: 0U,
    nonce: secret_words_from_array(nonce),
    block: secret_words_from_array(Array::make(16, 0U)),
    block_index: 16,
    secure_seeded,
    destroyed: false,
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
  if self.destroyed {
    return 0U
  }
  if self.block_index >= 16 {
    self.refill()
  }
  let value = secret_words_get(self.block, self.block_index)
  self.block_index = self.block_index + 1
  value
}

///|
/// Best-effort portable destruction. Native builds replace these arrays with
/// zeroizing external buffers in the hardened provider path; GC backends can
/// only overwrite the reachable storage and cannot promise immediate release.
pub fn RandomGenerator::destroy(self : RandomGenerator) -> Unit {
  secret_words_destroy(self.key)
  secret_words_destroy(self.nonce)
  secret_words_destroy(self.block)
  self.counter = 0U
  self.block_index = 16
  self.destroyed = true
}

///|
pub fn RandomGenerator::is_destroyed(self : RandomGenerator) -> Bool {
  self.destroyed
}

///|
pub fn RandomGenerator::next_u64(self : RandomGenerator) -> UInt64 {
  self.next_u32().to_uint64() | (self.next_u32().to_uint64() << 32)
}

///|
/// Versioned fixed-point cumulative distribution table. Production fixtures
/// use three UInt64 words (192 bits); compact toy fixtures retain two words.
pub struct DiscreteGaussian {
  priv sigma_q32 : UInt64
  priv tail_bound : Int
  priv cdt_length : Int
  priv threshold_words : Int
  priv cdt_chunks : Array[FixedArray[UInt64]]
  priv fixture_hash : String
}

///|
/// Validate caller-provided fixed-point CDT material once. Sampling from the
/// resulting opaque value is total and performs no structural error handling.
pub fn discrete_gaussian_from_cdt(
  sigma_q32 : UInt64,
  tail_bound : Int,
  threshold_words : Int,
  thresholds : FixedArray[UInt64],
  fixture_hash : String,
) -> Result[DiscreteGaussian, RandomError] {
  if sigma_q32 == 0UL ||
    tail_bound <= 0 ||
    (threshold_words != 2 && threshold_words != 3) ||
    thresholds.length() != (tail_bound + 1) * threshold_words ||
    fixture_hash.length() == 0 {
    return Err(InvalidDistribution)
  }
  let mut previous_top = 0UL
  let mut previous_high = 0UL
  let mut previous_low = 0UL
  for index in 0..<(tail_bound + 1) {
    let offset = index * threshold_words
    let top = if threshold_words == 3 { thresholds[offset] } else { 0UL }
    let high = thresholds[offset + threshold_words - 2]
    let low = thresholds[offset + threshold_words - 1]
    if index > 0 &&
      (
        top < previous_top ||
        (
          top == previous_top &&
          (
            high < previous_high ||
            (high == previous_high && low <= previous_low)
          )
        )
      ) {
      return Err(InvalidDistribution)
    }
    previous_top = top
    previous_high = high
    previous_low = low
  }
  if previous_high != 0xFFFFFFFFFFFFFFFFUL ||
    previous_low != 0xFFFFFFFFFFFFFFFFUL ||
    (threshold_words == 3 && previous_top != 0xFFFFFFFFFFFFFFFFUL) {
    return Err(InvalidDistribution)
  }
  Ok({
    sigma_q32,
    tail_bound,
    cdt_length: tail_bound + 1,
    threshold_words,
    cdt_chunks: [thresholds.copy()],
    fixture_hash,
  })
}

///|
/// The small sigma=3 fixture is used by toy key generation during C1. Standard
/// parameter tables are introduced together with their estimator records.
pub fn gaussian_sigma_3_fixture() -> DiscreteGaussian {
  {
    sigma_q32: 3UL << 32,
    tail_bound: 24,
    cdt_length: 25,
    threshold_words: 2,
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
    threshold_words: 2,
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
) -> Int {
  let draw_top = if distribution.threshold_words == 3 {
    self.next_u64()
  } else {
    0UL
  }
  let draw_high = self.next_u64()
  let draw_low = self.next_u64()
  let mut low = 0
  let mut high = distribution.cdt_length - 1
  while low < high {
    let middle = (low + high) / 2
    let (threshold_top, threshold_high, threshold_low) = distribution.cdt_threshold(
      middle,
    )
    if draw_top < threshold_top ||
      (
        draw_top == threshold_top &&
        (
          draw_high < threshold_high ||
          (draw_high == threshold_high && draw_low <= threshold_low)
        )
      ) {
      high = middle
    } else {
      low = middle + 1
    }
  }
  let magnitude = low
  if magnitude == 0 || (self.next_u32() & 1U) == 0U {
    magnitude
  } else {
    -magnitude
  }
}

///|
fn DiscreteGaussian::cdt_threshold(
  self : DiscreteGaussian,
  index : Int,
) -> (UInt64, UInt64, UInt64) {
  let chunk_index = index / 4096
  let word_index = index % 4096 * self.threshold_words
  let chunk = self.cdt_chunks[chunk_index]
  if self.threshold_words == 3 {
    (chunk[word_index], chunk[word_index + 1], chunk[word_index + 2])
  } else {
    (0UL, chunk[word_index], chunk[word_index + 1])
  }
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
  let width_u64 = width.to_uint64()
  let range = 0x100000000UL
  let limit = range - range % width_u64
  while true {
    let draw = self.next_u32().to_uint64()
    if draw < limit {
      return Ok((draw % width_u64).to_int() - bound)
    }
  }
  Err(InvalidDistribution)
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
    let sample = rng.sample_discrete_gaussian_fixed(distribution)
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
    actual.push(rng.sample_discrete_gaussian_fixed(distribution))
  }
  debug_inspect(
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
  assert_eq(low.tail_bound(), 65)
  assert_eq(high.tail_bound(), 231909)
  assert_true(low.fixture_hash().has_prefix("sha256:"))
  assert_true(high.fixture_hash().has_prefix("sha256:"))
  let rng = test_rng_new(0x5354414E44415244)
  for _ in 0..<128 {
    let low_sample = rng.sample_discrete_gaussian_fixed(low)
    assert_true(low_sample >= -65 && low_sample <= 65)
    let high_sample = rng.sample_discrete_gaussian_fixed(high)
    assert_true(high_sample >= -231909 && high_sample <= 231909)
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
      let sample = rng.sample_discrete_gaussian_fixed(distribution)
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
    actual.push(rng.sample_discrete_gaussian_fixed(low))
    actual.push(rng.sample_discrete_gaussian_fixed(high))
  }
  debug_inspect(
    actual,
    content=(
      #|[
      #|  13990,
      #|  32571,
      #|  27241,
      #|  -18993,
      #|  16097,
      #|  -24850,
      #|  -12036,
      #|  38092,
      #|  -19843,
      #|  -226,
      #|  6573,
      #|  5260,
      #|  23861,
      #|  -10408,
      #|  15017,
      #|  -16890,
      #|]
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

///|
test "random: TUniform rejection sampler preserves non-power-of-two support" {
  let rng = test_rng_new(0x54554E49464F524DUL)
  let mut seen_low = false
  let mut seen_high = false
  for _ in 0..<20000 {
    let value = rng.sample_tuniform(5).unwrap()
    assert_true(value >= -5 && value <= 5)
    if value == -5 {
      seen_low = true
    }
    if value == 5 {
      seen_high = true
    }
  }
  assert_true(seen_low)
  assert_true(seen_high)
}

///|
test "random: malformed CDT is rejected before sampling" {
  let malformed : FixedArray[UInt64] = FixedArray::from_array([
    0UL, 0UL, 0UL, 0xFFFFFFFFFFFFFFFFUL, 0UL, 0UL,
  ])
  assert_true(
    discrete_gaussian_from_cdt(
      1UL << 32,
      1,
      3,
      malformed,
      "test-only:malformed",
    )
    is Err(InvalidDistribution),
  )
}

///|
test "random: destroy clears the stream and makes reads inert" {
  let rng = test_rng_new(0x44455354524F59UL)
  ignore(rng.next_u32())
  rng.destroy()
  assert_true(rng.is_destroyed())
  assert_eq(rng.next_u32(), 0U)
}
