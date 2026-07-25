///|
test "polynomial: native RustFFT agrees with reference for full-width Torus32" {
  let left = [
    0U, 0xFFFF_FFFFU, 0x8000_0000U, 0x1234_5678U, 7U, 0xFFFF_0001U, 0x8000_0001U,
    19U,
  ].map(@torus.Torus32::from_uint)
  let right = [3U, 0xFFFF_FFFEU, 5U, 0x8000_0001U, 11U, 0x0001_FFFFU, 17U, 23U].map(
    @torus.Torus32::from_uint,
  )
  let expected = negacyclic_mul_reference(left, right).unwrap()
  let actual = negacyclic_mul_native_u32(left, right).unwrap()
  assert_eq(actual, expected)
}
