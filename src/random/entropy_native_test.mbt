///|
test "random: native generator is securely seeded" {
  let rng = secure_rng_new().unwrap()
  assert_true(rng.is_secure())
  let first = rng.next_u64()
  let second = rng.next_u64()
  assert_true(first != second)
  let noise = rng.sample_discrete_gaussian_fixed(gaussian_sigma_3_fixture())
  assert_true(noise >= -24 && noise <= 24)
}
