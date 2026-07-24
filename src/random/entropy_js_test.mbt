///|
test "random: JavaScript uses WebCrypto when no provider is installed" {
  clear_entropy_provider()
  let rng = secure_rng_new().unwrap()
  assert_true(rng.is_secure())
}
