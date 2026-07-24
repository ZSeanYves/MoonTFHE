///|
/// Independent reference for negacyclic multiplication. It intentionally uses
/// the coefficient formula rather than the production loop structure.
fn poly_mul_reference(a : Array[Int], b : Array[Int]) -> Array[Int] {
  if a.length() != b.length() {
    panic()
  }
  let n = a.length()
  let out = Array::make(n, 0)
  for k in 0..<n {
    let mut value = 0
    for i in 0..<n {
      let j = k - i
      if j >= 0 {
        value = value + a[i] * b[j]
      } else {
        value = value - a[i] * b[j + n]
      }
    }
    out[k] = value
  }
  out
}

///|
/// Map a Torus32 value to a power-of-two plaintext modulus by nearest rounding.
fn torus_modulus_switch(value : Int, log_modulus : Int) -> Int {
  if log_modulus <= 0 || log_modulus > 16 {
    panic()
  }
  let modulus : Int64 = 1L << log_modulus
  let unsigned = value.reinterpret_as_uint().to_int64()
  (((unsigned * modulus + 0x8000_0000L) >> 32) % modulus).to_int()
}

///|
/// Convert a power-of-two plaintext modulus value back to Torus32.
fn modulus_switch_to_torus(value : Int, log_modulus : Int) -> Int {
  if log_modulus <= 0 || log_modulus > 16 {
    panic()
  }
  let shifted = value.to_int64() << (32 - log_modulus)
  shifted.reinterpret_as_uint64().to_uint().reinterpret_as_int()
}

///|
/// Signed centered gadget decomposition used as a P1 reference contract.
fn signed_decompose_reference(
  value : Int,
  base_log : Int,
  level : Int,
) -> Array[Int] {
  if base_log <= 0 || base_log > 16 || level <= 0 || base_log * level > 32 {
    panic()
  }
  let base : Int64 = 1L << base_log
  let half = base >> 1
  let mask = base - 1L
  let mut remaining = value.reinterpret_as_uint().to_int64()
  let digits = Array::make(level, 0)
  for i in 0..<level {
    let raw = remaining & mask
    if raw >= half {
      digits[i] = (raw - base).to_int()
      remaining = (remaining >> base_log) + 1L
    } else {
      digits[i] = raw.to_int()
      remaining = remaining >> base_log
    }
  }
  digits
}

///|
test "reference: candidate polynomial multiplication agrees" {
  let cases : Array[(Array[Int], Array[Int])] = [
    ([1, 2, 0, -1], [3, 0, 4, 1]),
    ([0, 7, -2, 5], [6, -1, 3, 0]),
    ([11, -4, 8, 2], [-3, 9, 1, -6]),
  ]
  for case in cases {
    let (left, right) = case
    assert_eq(poly_mul_negacyclic(left, right), poly_mul_reference(left, right))
  }
}

///|
test "reference: modulus switching has explicit boundary behavior" {
  for log_modulus in 1..<=8 {
    let modulus = 1 << log_modulus
    assert_eq(torus_modulus_switch(0, log_modulus), 0)
    assert_eq(torus_modulus_switch(T32_QUARTER, log_modulus), (modulus + 2) / 4)
    assert_eq(torus_modulus_switch(T32_HALF - 1, log_modulus), modulus / 2)
    for message in 0..<modulus {
      let torus = modulus_switch_to_torus(message, log_modulus)
      assert_eq(torus_modulus_switch(torus, log_modulus), message)
    }
  }
}

///|
test "reference: signed decomposition stays centered and recomposes" {
  let values = [0, 1, -1, T32_QUARTER, -T32_QUARTER, T32_HALF - 1]
  for value in values {
    let base_log = 4
    let level = 8
    let digits = signed_decompose_reference(value, base_log, level)
    let base = 1 << base_log
    for digit in digits {
      assert_true(digit >= -(base / 2) && digit < base / 2)
    }
    let mut recomposed : Int64 = 0L
    let mut factor : Int64 = 1L
    for digit in digits {
      recomposed = recomposed + digit.to_int64() * factor
      factor = factor * base.to_int64()
    }
    assert_eq(
      recomposed.reinterpret_as_uint64().to_uint().reinterpret_as_int(),
      value,
    )
  }
}
