///|
test "lwe: encrypt/decrypt roundtrip (n=512, 400 trials)" {
  let rng = @rng.csprng_new(123456789)
  let key = lwe_key_new(512, rng)
  let trials = 400
  let mut ok = 0
  for _i in 0..<trials {
    let bit = (@rng.next_u64(rng) & 1) == 1
    // sigma 较小，避免解密错误
    let ct = lwe_encrypt(key, bit, 3.0, rng)
    let dec = lwe_decrypt(key, ct)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}
