test "torus: wrap-around add/sub" {
  let a = 0xFFFF_FFFF   // -1 mod 2^32
  let b = 2
  assert_eq(t32_add(a, b), 1)

  let z = 0
  assert_eq(t32_sub(z, 1), 0xFFFF_FFFF)
}

test "torus: bool <-> torus encoding" {
  assert_eq(bool_to_t32(true),  0x0000_0000)
  assert_eq(bool_to_t32(false), T32_HALF)

  // decode threshold at 0.5
  assert_eq(t32_to_bool(0x7FFF_FFFF), true)
  assert_eq(t32_to_bool(0x8000_0000), false)
  assert_eq(t32_to_bool(0x8000_0001), false)
}

test "torus: f64_to_t32 — canonical points & periodicity" {
  assert_eq(f64_to_t32(0.0),  0x0000_0000)
  assert_eq(f64_to_t32(0.25), 0x4000_0000)
  assert_eq(f64_to_t32(0.5),  0x8000_0000)

  // periodic: x ≡ x + k
  assert_eq(f64_to_t32(1.25), 0x4000_0000)
  assert_eq(f64_to_t32(2.5),  0x8000_0000)
}

test "torus: f64_to_t32 — negatives map correctly to [0,1)" {
  // -0.25 ↦ 0.75
  assert_eq(f64_to_t32(-0.25), 0xC000_0000)
  // -1.0 ↦ 0
  assert_eq(f64_to_t32(-1.0), 0x0000_0000)
  // -1.5 ↦ 0.5
  assert_eq(f64_to_t32(-1.5), 0x8000_0000)
}

test "torus: scalar mul (small k) wraps as expected" {
  let q = 0x4000_0000   // 0.25
  assert_eq(t32_mul_k(q, 2), 0x8000_0000)   // 0.5
  assert_eq(t32_mul_k(q, 4), 0x0000_0000)   // 1.0 -> 0 mod 1
}
