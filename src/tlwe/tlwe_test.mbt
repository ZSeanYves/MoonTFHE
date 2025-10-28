///|
test "tlwe: encrypt/decrypt roundtrip (n=512, 200 trials)" {
  let rng = @rng.csprng_new(20241028)
  let n = 512
  let key = tlwe_key_new(n, rng)
  let trials = 200
  let sigma = 3.0 // 小噪声，远小于 ±0.25 的安全边界
  let mut ok = 0
  for _i in 0..<trials {
    let bit = (@rng.next_u64(rng) & 1) == 1
    let m = tlwe_encode_bit_const(n, bit)
    let ct = tlwe_encrypt(key, m, sigma.to_float(), rng)
    let dec = tlwe_decrypt_bit0(key, ct)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}
