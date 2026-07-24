///|
test "random: portable backend requires an explicit entropy adapter" {
  clear_entropy_provider()
  assert_true(secure_rng_new() is Err(UnsupportedBackend))
}
