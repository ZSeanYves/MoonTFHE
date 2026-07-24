///|
pub suberror PolynomialError {
  LengthMismatch
  EmptyPolynomial
  NonPowerOfTwo
} derive(Debug, Eq)

///|
/// Coefficient-by-coefficient negacyclic multiplication in Z[X]/(X^N + 1).
pub fn negacyclic_mul_reference(
  left : Array[@torus.Torus32],
  right : Array[@torus.Torus32],
) -> Result[Array[@torus.Torus32], PolynomialError] {
  if left.length() != right.length() {
    return Err(LengthMismatch)
  }
  let n = left.length()
  if n == 0 {
    return Err(EmptyPolynomial)
  }
  if (n & (n - 1)) != 0 {
    return Err(NonPowerOfTwo)
  }
  let output = Array::make(n, @torus.Torus32::zero())
  for k in 0..<n {
    let mut value = @torus.Torus32::zero()
    for i in 0..<n {
      let j = k - i
      let term = left[i].scale(right[if j >= 0 { j } else { j + n }].to_int())
      value = if j >= 0 { value.add(term) } else { value.sub(term) }
    }
    output[k] = value
  }
  Ok(output)
}

///|
pub fn negacyclic_rotate_reference(
  input : Array[@torus.Torus32],
  rotation : Int,
) -> Result[Array[@torus.Torus32], PolynomialError] {
  let n = input.length()
  if n == 0 {
    return Err(EmptyPolynomial)
  }
  if (n & (n - 1)) != 0 {
    return Err(NonPowerOfTwo)
  }
  let period = 2 * n
  let exponent = (rotation % period + period) % period
  let negate = exponent >= n
  let shift = exponent % n
  let output = Array::make(n, @torus.Torus32::zero())
  for i in 0..<n {
    let destination = i + shift
    let coefficient = if negate { input[i].neg() } else { input[i] }
    if destination < n {
      output[destination] = output[destination].add(coefficient)
    } else {
      output[destination - n] = output[destination - n].sub(coefficient)
    }
  }
  Ok(output)
}
