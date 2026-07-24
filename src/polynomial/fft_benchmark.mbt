///|
test "bench polynomial FFT candidate n=128" (bench : @bench.T) {
  let left = Array::makei(128, fn(i) { @torus.Torus32::from_int(i % 7 - 3) })
  let right = Array::makei(128, fn(i) { @torus.Torus32::from_int(i % 11 - 5) })
  bench.bench(fn() { bench.keep(negacyclic_mul_fft(left, right)) })
}
