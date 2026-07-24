///|
test "bench polynomial negacyclic n=128" (bench : @bench.T) {
  let left = Array::makei(128, fn(i) { i % 7 - 3 })
  let right = Array::makei(128, fn(i) { i % 11 - 5 })
  bench.bench(fn() { bench.keep(poly_mul_negacyclic(left, right)) })
}

///|
test "bench TRGSW external product n=32" (bench : @bench.T) {
  let rng = csprng_new(0x42454E4348)
  let n = 32
  let params : TrgswParams = { base_log: 4, level: 8, n }
  let key = trlwe_key_new(n, rng)
  let g = trgsw_encrypt_bool(params, key, true, 0.0, rng)
  let message = trlwe_encrypt(key, trlwe_encode_bit_const(n, true), 0.0, rng)
  bench.bench(fn() { bench.keep(external_product(g, message)) })
}
