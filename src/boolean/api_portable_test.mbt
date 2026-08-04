///|
test "stable Boolean facade: portable standard keygen requires host entropy" {
  // Override the JS WebCrypto/Wasm host capability so this test exercises the
  // explicit missing-provider contract on every portable target.
  @random.install_entropy_provider(fn(_count) { None })
  assert_true(
    generate_keys(boolean_110_parameters()) is Err(UnsupportedBackend),
  )
  @random.clear_entropy_provider()
}
