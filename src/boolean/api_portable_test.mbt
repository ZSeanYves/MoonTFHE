///|
test "stable Boolean facade: portable standard keygen requires host entropy" {
  @random.clear_entropy_provider()
  assert_true(
    generate_keys(boolean_110_parameters()) is Err(UnsupportedBackend),
  )
}
