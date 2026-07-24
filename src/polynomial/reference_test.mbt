///|
test "polynomial: reference multiplication has independent coefficients" {
  let left = [
    @torus.Torus32::from_int(1),
    @torus.Torus32::from_int(2),
    @torus.Torus32::from_int(0),
    @torus.Torus32::from_int(-1),
  ]
  let right = [
    @torus.Torus32::from_int(3),
    @torus.Torus32::from_int(0),
    @torus.Torus32::from_int(4),
    @torus.Torus32::from_int(1),
  ]
  let result = negacyclic_mul_reference(left, right).unwrap()
  assert_eq(result.map(fn(x) { x.to_int() }), [1, 10, 5, 6])
}

///|
test "polynomial: rotations obey X^N = -1" {
  let input = [
    @torus.Torus32::from_int(1),
    @torus.Torus32::from_int(2),
    @torus.Torus32::from_int(3),
    @torus.Torus32::from_int(4),
  ]
  let result = negacyclic_rotate_reference(input, 4).unwrap()
  assert_eq(result.map(fn(x) { x.to_int() }), [-1, -2, -3, -4])
}
