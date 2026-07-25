///|
/// Errors returned while constructing an encrypted client-secret payload.
pub suberror SecretExportError {
  UnsupportedBackend
  InvalidLength
  ProviderFailure
} derive(Debug, Eq)

///|
/// Encrypt the secret payload without exposing plaintext secret bytes to the
/// Boolean facade. The payload is assembled and passed directly to the
/// selected AES-256-GCM provider.
pub fn ExperimentalBooleanClientKey::encrypt_secret_payload(
  self : ExperimentalBooleanClientKey,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
) -> Result[Bytes, SecretExportError] {
  if key.length() != 32 || nonce.length() != 12 {
    return Err(InvalidLength)
  }
  let dimension = self.lwe_key.s.length()
  let bit_bytes = (dimension + 7) / 8
  let payload = Array::make(9 + bit_bytes, b'\x00')
  payload[0] = b'M'
  payload[1] = b'S'
  payload[2] = b'C'
  payload[3] = b'R'
  payload[4] = b'\x01'
  boolean_write_i32_le(payload, 5, dimension)
  for index in 0..<dimension {
    if self.lwe_key.s[index] {
      let byte_index = index / 8
      let bit_index = index % 8
      payload[9 + byte_index] = payload[9 + byte_index] |
        (1U << bit_index).to_byte()
    }
  }
  match
    @provider.aes256_gcm_encrypt(key, nonce, aad, Bytes::from_array(payload)) {
    Ok(value) => Ok(value)
    Err(@provider.UnsupportedBackend) => Err(UnsupportedBackend)
    Err(@provider.InvalidLength) => Err(InvalidLength)
    Err(@provider.InvalidPolynomialSize) => Err(ProviderFailure)
    Err(@provider.AuthenticationFailed) => Err(ProviderFailure)
    Err(@provider.ProviderFailure(status~)) => {
      let _ = status
      Err(ProviderFailure)
    }
  }
}

///|
fn server_payload_push_u32(output : Array[Byte], value : UInt) -> Unit {
  output.push(value.to_byte())
  output.push((value >> 8).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 24).to_byte())
}

///|
fn server_payload_push_i32(output : Array[Byte], value : Int) -> Unit {
  server_payload_push_u32(output, value.reinterpret_as_uint())
}

///|
/// Serialize only public evaluation material. No LWE/TRLWE secret array is
/// traversed here; the payload contains encrypted TRGSW/KSK ciphertexts.
pub fn ExperimentalBooleanServerKey::serialize_payload(
  self : ExperimentalBooleanServerKey,
) -> Bytes {
  let output : Array[Byte] = []
  output.push(b'M')
  output.push(b'S')
  output.push(b'K')
  output.push(b'P')
  output.push(b'\x01')
  server_payload_push_i32(output, self.params.n_lwe_in)
  server_payload_push_i32(output, self.params.n_trlwe)
  server_payload_push_i32(output, self.bsk.params.base_log)
  server_payload_push_i32(output, self.bsk.params.level)
  server_payload_push_i32(output, self.key_tag)
  server_payload_push_i32(output, self.bsk.trgsw_data.length())
  for g in self.bsk.trgsw_data {
    server_payload_push_i32(output, g.params.base_log)
    server_payload_push_i32(output, g.params.level)
    server_payload_push_i32(output, g.params.n)
    server_payload_push_i32(output, g.data.length())
    for ct in g.data {
      server_payload_push_i32(output, ct.params.n)
      server_payload_push_i32(output, ct.a.length())
      for value in ct.a {
        server_payload_push_i32(output, value)
      }
      server_payload_push_i32(output, ct.b.length())
      for value in ct.b {
        server_payload_push_i32(output, value)
      }
    }
  }
  server_payload_push_i32(output, self.bsk.key_switch.params.base_log)
  server_payload_push_i32(output, self.bsk.key_switch.params.level)
  server_payload_push_i32(output, self.bsk.key_switch.n_in)
  server_payload_push_i32(output, self.bsk.key_switch.n_out)
  server_payload_push_i32(output, self.bsk.key_switch.data.length())
  for ct in self.bsk.key_switch.data {
    server_payload_push_i32(output, ct.a.length())
    for value in ct.a {
      server_payload_push_i32(output, value)
    }
    server_payload_push_i32(output, ct.b)
  }
  Bytes::from_array(output)
}
