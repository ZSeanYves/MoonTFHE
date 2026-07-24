///|
/// Recover an LWE phase using secret bits from the legacy test fixture.
fn oracle_phase(key : LweKey, ciphertext : LweCiphertext) -> Int {
  let mut dot = 0
  for i in 0..<key.s.length() {
    if key.s[i] {
      dot = t32_add(dot, ciphertext.a[i])
    }
  }
  t32_sub(ciphertext.b, dot)
}

///|
/// Reference-only trivial encryption under the same LWE dimension.
fn oracle_encode(dimension : Int, message : Bool) -> LweCiphertext {
  { a: Array::make(dimension, 0), b: t32_encode_bit_pm(message, T32_QUARTER) }
}

///|
fn oracle_decode(key : LweKey, ciphertext : LweCiphertext) -> Bool {
  t32_decode_sign(oracle_phase(key, ciphertext))
}

///|
fn tfhe_id_oracle_reference(
  _params : TfheParams,
  key : LweKey,
  ciphertext : LweCiphertext,
) -> LweCiphertext {
  oracle_encode(key.s.length(), oracle_decode(key, ciphertext))
}

///|
fn tfhe_not_oracle_reference(
  _params : TfheParams,
  key : LweKey,
  ciphertext : LweCiphertext,
) -> LweCiphertext {
  oracle_encode(key.s.length(), !oracle_decode(key, ciphertext))
}

///|
fn tfhe_xnor_oracle_reference(
  _params : TfheParams,
  key : LweKey,
  left : LweCiphertext,
  right : LweCiphertext,
) -> LweCiphertext {
  oracle_encode(
    key.s.length(),
    oracle_decode(key, left) == oracle_decode(key, right),
  )
}

///|
fn tfhe_xor_oracle_reference(
  _params : TfheParams,
  key : LweKey,
  left : LweCiphertext,
  right : LweCiphertext,
) -> LweCiphertext {
  oracle_encode(
    key.s.length(),
    oracle_decode(key, left) != oracle_decode(key, right),
  )
}

///|
test "oracle reference: unary and binary truth tables" {
  let rng = csprng_new(0x4F5241434C45)
  let params = tfhe_params_tiny_trlwe()
  let key_lwe = lwe_key_new(params.n_lwe_in, rng)
  for left in [false, true] {
    let encrypted_left = lwe_encrypt(key_lwe, left, 0.0, rng)
    assert_eq(
      lwe_decrypt(
        key_lwe,
        tfhe_id_oracle_reference(params, key_lwe, encrypted_left),
      ),
      left,
    )
    assert_eq(
      lwe_decrypt(
        key_lwe,
        tfhe_not_oracle_reference(params, key_lwe, encrypted_left),
      ),
      !left,
    )
    for right in [false, true] {
      let encrypted_right = lwe_encrypt(key_lwe, right, 0.0, rng)
      assert_eq(
        lwe_decrypt(
          key_lwe,
          tfhe_xnor_oracle_reference(
            params, key_lwe, encrypted_left, encrypted_right,
          ),
        ),
        left == right,
      )
      assert_eq(
        lwe_decrypt(
          key_lwe,
          tfhe_xor_oracle_reference(
            params, key_lwe, encrypted_left, encrypted_right,
          ),
        ),
        left != right,
      )
    }
  }
}
