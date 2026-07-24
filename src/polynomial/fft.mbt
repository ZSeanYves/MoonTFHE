///|
fn fft_in_place(
  real : Array[Double],
  imag : Array[Double],
  inverse : Bool,
) -> Unit {
  let n = real.length()
  let mut j = 0
  for i in 1..<n {
    let mut bit = n >> 1
    while (j & bit) != 0 {
      j = j ^ bit
      bit = bit >> 1
    }
    j = j ^ bit
    if i < j {
      let tr = real[i]
      real[i] = real[j]
      real[j] = tr
      let ti = imag[i]
      imag[i] = imag[j]
      imag[j] = ti
    }
  }
  let mut length = 2
  while length <= n {
    let sign = if inverse { 1.0 } else { -1.0 }
    let angle = sign * 2.0 * @math.PI / Double::from_int(length)
    let wlen_real = @math.cos(angle)
    let wlen_imag = @math.sin(angle)
    let half = length >> 1
    let mut start = 0
    while start < n {
      let mut w_real = 1.0
      let mut w_imag = 0.0
      for offset in 0..<half {
        let even = start + offset
        let odd = even + half
        let product_real = real[odd] * w_real - imag[odd] * w_imag
        let product_imag = real[odd] * w_imag + imag[odd] * w_real
        let even_real = real[even]
        let even_imag = imag[even]
        real[even] = even_real + product_real
        imag[even] = even_imag + product_imag
        real[odd] = even_real - product_real
        imag[odd] = even_imag - product_imag
        let next_real = w_real * wlen_real - w_imag * wlen_imag
        w_imag = w_real * wlen_imag + w_imag * wlen_real
        w_real = next_real
      }
      start = start + length
    }
    length = length << 1
  }
  if inverse {
    let scale = 1.0 / Double::from_int(n)
    for i in 0..<n {
      real[i] = real[i] * scale
      imag[i] = imag[i] * scale
    }
  }
}

///|
/// FFT candidate for negacyclic multiplication. It embeds X^N + 1 into a
/// cyclic transform of length 2N and folds the upper half with a negative sign.
/// This implementation is exact for the small/reference coefficient range;
/// large Torus32 products require split-precision or the native backend.
pub fn negacyclic_mul_fft(
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
  let size = 2 * n
  let left_real = Array::make(size, 0.0)
  let left_imag = Array::make(size, 0.0)
  let right_real = Array::make(size, 0.0)
  let right_imag = Array::make(size, 0.0)
  for i in 0..<n {
    left_real[i] = Double::from_int(left[i].to_int())
    right_real[i] = Double::from_int(right[i].to_int())
  }
  fft_in_place(left_real, left_imag, false)
  fft_in_place(right_real, right_imag, false)
  for i in 0..<size {
    let real = left_real[i] * right_real[i] - left_imag[i] * right_imag[i]
    let imag = left_real[i] * right_imag[i] + left_imag[i] * right_real[i]
    left_real[i] = real
    left_imag[i] = imag
  }
  fft_in_place(left_real, left_imag, true)
  Ok(
    Array::makei(n, fn(k) {
      @torus.Torus32::from_int(
        (left_real[k] - left_real[k + n]).round().to_int(),
      )
    }),
  )
}

///|
test "polynomial: FFT candidate matches reference" {
  let cases : Array[(Array[@torus.Torus32], Array[@torus.Torus32])] = [
    (
      [1, 2, 0, -1].map(@torus.Torus32::from_int),
      [3, 0, 4, 1].map(@torus.Torus32::from_int),
    ),
    (
      [0, 7, -2, 5, 1, -3, 2, 4].map(@torus.Torus32::from_int),
      [6, -1, 3, 0, 4, 2, -5, 1].map(@torus.Torus32::from_int),
    ),
  ]
  for case in cases {
    let (left, right) = case
    let reference = negacyclic_mul_reference(left, right).unwrap()
    let candidate = negacyclic_mul_fft(left, right).unwrap()
    assert_eq(
      candidate.map(fn(x) { x.to_int() }),
      reference.map(fn(x) { x.to_int() }),
    )
  }
}
