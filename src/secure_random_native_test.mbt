///|
test "secure rng native: entropy and gaussian path" {
  let rng = match secure_rng_new() {
    Ok(rng) => rng
    Err(_) => fail("native entropy unavailable")
  }
  let first = match rng.next_u64() {
    Ok(value) => value
    Err(_) => fail("native entropy read failed")
  }
  let second = match rng.next_u64() {
    Ok(value) => value
    Err(_) => fail("native entropy read failed")
  }
  assert_true(first != second)
  let mut nonzero = 0
  for _ in 0..<64 {
    let sample = match rng.gaussian(3.0) {
      Ok(sample) => sample
      Err(_) => fail("native gaussian read failed")
    }
    if sample != 0 {
      nonzero = nonzero + 1
    }
  }
  assert_true(nonzero > 0)
}
