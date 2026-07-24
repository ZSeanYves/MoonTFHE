///|
/// Errors detected at the opaque Boolean ciphertext boundary.
pub suberror BooleanCiphertextError {
  InvalidMagic
  UnsupportedVersion
  InvalidLength
  DimensionMismatch
  KeyMismatch
} derive(Debug, Eq)

///|
/// Client-side secret material for the deterministic Boolean prototype.
///
/// This type is deliberately named experimental: its key generation and
/// encryption still use TestRng and zero noise, so it is not secure.
pub struct ExperimentalBooleanClientKey {
  params : TfheParams
  lwe_key : LweKey
  rng : CsPrng
  key_tag : Int
}

///|
/// Secret-free server-side evaluation material.
pub struct ExperimentalBooleanServerKey {
  params : TfheParams
  bsk : BootstrappingKey
  key_tag : Int
}

///|
/// Opaque Boolean ciphertext accepted by the experimental Boolean facade.
pub struct BooleanCiphertext {
  inner : LweCiphertext
  key_tag : Int
}

///|
fn experimental_boolean_params() -> TfheParams {
  {
    n_lwe_in: 4,
    n_lwe_out: 4,
    sigma_lwe: 0.0,
    ks_base_log: 4,
    ks_level: 8,
    sigma_ks: 0.0,
    n_trlwe: 32,
    sigma_trlwe: 0.0,
    bk_base_log: 4,
    bk_level: 8,
  }
}

///|
/// Generate deterministic client/server keys for examples and tests.
///
/// The returned server key contains only encrypted GGSW and key-switching
/// material. The seed makes this API reproducible and therefore unsuitable
/// for sensitive data.
pub fn experimental_boolean_keygen(
  seed : UInt64,
) -> (ExperimentalBooleanClientKey, ExperimentalBooleanServerKey) {
  let params = experimental_boolean_params()
  let rng = csprng_new(seed)
  let key_tag = next_u32(rng)
  let lwe_key = lwe_key_new(params.n_lwe_in, rng)
  let trlwe_key = trlwe_key_new(params.n_trlwe, rng)
  let bsk = bsk_generate(
    params,
    lwe_key,
    trlwe_key,
    params.bk_base_log,
    params.bk_level,
    params.sigma_trlwe,
    rng,
  )
  ({ params, lwe_key, rng, key_tag }, { params, bsk, key_tag })
}

///|
pub fn ExperimentalBooleanClientKey::encrypt(
  self : ExperimentalBooleanClientKey,
  message : Bool,
) -> BooleanCiphertext {
  {
    inner: lwe_encrypt_with_mu(
      self.lwe_key,
      message,
      T32_EIGHTH,
      self.params.sigma_lwe,
      self.rng,
    ),
    key_tag: self.key_tag,
  }
}

///|
pub fn ExperimentalBooleanClientKey::decrypt(
  self : ExperimentalBooleanClientKey,
  ciphertext : BooleanCiphertext,
) -> Result[Bool, BooleanCiphertextError] {
  if ciphertext.key_tag != self.key_tag {
    return Err(KeyMismatch)
  }
  if ciphertext.inner.a.length() != self.params.n_lwe_in {
    return Err(DimensionMismatch)
  }
  Ok(lwe_decrypt(self.lwe_key, ciphertext.inner))
}

///|
pub fn ExperimentalBooleanServerKey::not(
  self : ExperimentalBooleanServerKey,
  ciphertext : BooleanCiphertext,
) -> Result[BooleanCiphertext, BooleanCiphertextError] {
  if ciphertext.key_tag != self.key_tag {
    return Err(KeyMismatch)
  }
  if ciphertext.inner.a.length() != self.params.n_lwe_in {
    return Err(DimensionMismatch)
  }
  Ok({
    inner: tfhe_not(self.params, self.bsk, ciphertext.inner),
    key_tag: self.key_tag,
  })
}

///|
pub fn ExperimentalBooleanServerKey::nand(
  self : ExperimentalBooleanServerKey,
  left : BooleanCiphertext,
  right : BooleanCiphertext,
) -> Result[BooleanCiphertext, BooleanCiphertextError] {
  if left.key_tag != self.key_tag || right.key_tag != self.key_tag {
    return Err(KeyMismatch)
  }
  if left.inner.a.length() != self.params.n_lwe_in ||
    right.inner.a.length() != self.params.n_lwe_in {
    return Err(DimensionMismatch)
  }
  Ok({
    inner: tfhe_nand(self.params, self.bsk, left.inner, right.inner),
    key_tag: self.key_tag,
  })
}

///|
fn boolean_write_i32_le(
  output : Array[Byte],
  offset : Int,
  value : Int,
) -> Unit {
  output[offset] = value.to_byte()
  output[offset + 1] = (value >> 8).to_byte()
  output[offset + 2] = (value >> 16).to_byte()
  output[offset + 3] = (value >> 24).to_byte()
}

///|
fn boolean_read_i32_le(input : Bytes, offset : Int) -> Int {
  input[offset].to_int() |
  (input[offset + 1].to_int() << 8) |
  (input[offset + 2].to_int() << 16) |
  (input[offset + 3].to_int() << 24)
}

///|
/// Serialize one ciphertext using the versioned `MTFH` binary format.
/// Secret keys and server keys intentionally have no serialization API.
pub fn BooleanCiphertext::serialize(self : BooleanCiphertext) -> Bytes {
  let dimension = self.inner.a.length()
  let output = Array::make(13 + 4 * (dimension + 1), b'\x00')
  output[0] = b'M'
  output[1] = b'T'
  output[2] = b'F'
  output[3] = b'H'
  output[4] = b'\x01'
  boolean_write_i32_le(output, 5, dimension)
  boolean_write_i32_le(output, 9, self.key_tag)
  for i in 0..<dimension {
    boolean_write_i32_le(output, 13 + 4 * i, self.inner.a[i])
  }
  boolean_write_i32_le(output, 13 + 4 * dimension, self.inner.b)
  Bytes::from_array(output)
}

///|
/// Decode and validate a ciphertext for this client key.
pub fn ExperimentalBooleanClientKey::deserialize_ciphertext(
  self : ExperimentalBooleanClientKey,
  input : Bytes,
) -> Result[BooleanCiphertext, BooleanCiphertextError] {
  if input.length() < 13 {
    return Err(InvalidLength)
  }
  if input[0] != b'M' ||
    input[1] != b'T' ||
    input[2] != b'F' ||
    input[3] != b'H' {
    return Err(InvalidMagic)
  }
  if input[4] != b'\x01' {
    return Err(UnsupportedVersion)
  }
  let dimension = boolean_read_i32_le(input, 5)
  if dimension != self.params.n_lwe_in {
    return Err(DimensionMismatch)
  }
  if input.length() != 13 + 4 * (dimension + 1) {
    return Err(InvalidLength)
  }
  let key_tag = boolean_read_i32_le(input, 9)
  if key_tag != self.key_tag {
    return Err(KeyMismatch)
  }
  let a = Array::makei(dimension, fn(i) {
    boolean_read_i32_le(input, 13 + 4 * i)
  })
  let b = boolean_read_i32_le(input, 13 + 4 * dimension)
  Ok({ inner: { a, b }, key_tag })
}
