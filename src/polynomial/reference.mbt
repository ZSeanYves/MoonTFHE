///|
pub suberror PolynomialError {
  LengthMismatch
  EmptyPolynomial
  NonPowerOfTwo
  UnsupportedBackend
  ProviderFailure
} derive(Debug, Eq)

///|
/// Native RustFFT candidate. Portable backends return UnsupportedBackend and
/// callers can use `negacyclic_mul_reference` without changing semantics.
pub fn negacyclic_mul_native_u32(
  left : Array[@torus.Torus32],
  right : Array[@torus.Torus32],
) -> Result[Array[@torus.Torus32], PolynomialError] {
  if left.length() != right.length() {
    return Err(LengthMismatch)
  }
  if left.length() == 0 {
    return Err(EmptyPolynomial)
  }
  if (left.length() & (left.length() - 1)) != 0 {
    return Err(NonPowerOfTwo)
  }
  let plan = match @provider.fft_plan_new(left.length()) {
    Ok(value) => value
    Err(@provider.UnsupportedBackend) => return Err(UnsupportedBackend)
    Err(@provider.InvalidLength) => return Err(LengthMismatch)
    Err(@provider.InvalidPolynomialSize) => return Err(NonPowerOfTwo)
    Err(@provider.AuthenticationFailed) => return Err(ProviderFailure)
    Err(@provider.ProviderFailure(status~)) => {
      let _ = status
      return Err(ProviderFailure)
    }
  }
  let left_flat = FixedArray::makei(left.length(), fn(index) {
    left[index].to_uint()
  })
  let right_flat = FixedArray::makei(right.length(), fn(index) {
    right[index].to_uint()
  })
  let output = FixedArray::make(left.length(), 0U)
  match plan.negacyclic_mul_u32(left_flat, right_flat, output) {
    Ok(_) => ()
    Err(@provider.UnsupportedBackend) => return Err(UnsupportedBackend)
    Err(@provider.InvalidLength) => return Err(LengthMismatch)
    Err(@provider.InvalidPolynomialSize) => return Err(NonPowerOfTwo)
    Err(@provider.AuthenticationFailed) => return Err(ProviderFailure)
    Err(@provider.ProviderFailure(status~)) => {
      let _ = status
      return Err(ProviderFailure)
    }
  }
  Ok(
    Array::makei(output.length(), fn(index) {
      @torus.Torus32::from_uint(output[index])
    }),
  )
}

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
