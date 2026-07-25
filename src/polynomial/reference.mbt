///|
pub suberror PolynomialError {
  LengthMismatch
  EmptyPolynomial
  NonPowerOfTwo
  UnsupportedBackend
  ProviderFailure
} derive(Debug, Eq)

///|
fn torus_array_to_u32_le(values : Array[@torus.Torus32]) -> Bytes {
  let output = Array::make(values.length() * 4, b'\x00')
  for index in 0..<values.length() {
    let value = values[index].to_uint()
    output[index * 4] = value.to_byte()
    output[index * 4 + 1] = (value >> 8).to_byte()
    output[index * 4 + 2] = (value >> 16).to_byte()
    output[index * 4 + 3] = (value >> 24).to_byte()
  }
  Bytes::from_array(output)
}

///|
fn u32_le_to_torus_array(
  bytes : Bytes,
  count : Int,
) -> Result[Array[@torus.Torus32], PolynomialError] {
  if bytes.length() != count * 4 {
    return Err(ProviderFailure)
  }
  Ok(
    Array::makei(count, fn(index) {
      @torus.Torus32::from_uint(
        bytes[index * 4].to_uint() |
        (bytes[index * 4 + 1].to_uint() << 8) |
        (bytes[index * 4 + 2].to_uint() << 16) |
        (bytes[index * 4 + 3].to_uint() << 24),
      )
    }),
  )
}

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
  let output = match
    plan.negacyclic_mul_u32_le(
      torus_array_to_u32_le(left),
      torus_array_to_u32_le(right),
    ) {
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
  u32_le_to_torus_array(output, left.length())
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
