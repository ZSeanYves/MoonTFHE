// 0.5 in Q1.31，用作布尔阈值
///|
const T32_HALF : Int = 0x8000_0000
// 额外常量：0.25 in Q1.31
///|
const T32_QUARTER : Int = 0x4000_0000

// 基本运算（自然溢出即模 2^32）
///|
fn t32_add(a : Int, b : Int) -> Int {
  a + b
}
///|
fn t32_sub(a : Int, b : Int) -> Int {
  a - b
}
///|
fn t32_mul_k(a : Int, k : Int) -> Int {
  a * k
}



// 布尔相位编码：true -> 0，false -> 0.5
///|
fn bool_to_t32(b : Bool) -> Int {
  if b {
    0x0000_0000
  } else {
    T32_HALF
  }
}
// 布尔相位解码：（非负 => [0,0.5) => true；负数 => [0.5,1) => false）
///|
fn t32_to_bool(mu : Int) -> Bool {
  mu >= 0
}

///|
fn t32_mul(a : Int, b : Int) -> Int {
  let a64 = a.reinterpret_as_uint().to_int64()
  let b64 = b.reinterpret_as_uint().to_int64()
  let prod = (a64 * b64) >> 32
  prod.to_int()
}




// 对称编码：true -> +mu, false -> -mu  
// PS: mu 建议取 T32_QUARTER
///|
fn t32_encode_bit_pm(b : Bool, mu : Int) -> Int {
  if b {
    mu
  } else {
    -mu
  }
}
// 对称解码：看符号位（>=0 为 true）
///|
fn t32_decode_sign(x : Int) -> Bool {
  x >= 0
}





// 将任意浮点 x 映射到 [0,1) 再编码到 Q1.31（避免 2^31 溢出/饱和）
///|
fn f64_to_t32(x : Float) -> Int {
  // 先得到 frac ∈ [0,1)
  let frac = if x >= 0.0 {
    let xi = x.to_int()
    x - xi.to_float()
  } else {
    // x = -a；(-a) mod 1 = (1 - frac(a)) mod 1
    let a = -x
    let ai = a.to_int()
    let af = a - ai.to_float() // ∈ [0,1)
    if af == 0.0 {
      0.0
    } else {
      1.0 - af
    }
  }
  if frac < 0.5 {
    // 左半区：结果 < 2^31，直接转换
    (frac * 4294967296.0).to_int()
  } else {
    // 右半区：从 0.5 起的偏移，最大到 2^31-ε
    let delta = ((frac - 0.5) * 4294967296.0).to_int()
    0x8000_0000 + delta
  }
}

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

test "torus: t32_mul basic wrap" {
  let x = T32_HALF   // 0.5
  let y = T32_HALF   // 0.5
  let z = t32_mul(x, y)  // Expect ≈ 0.25 → 0x4000_0000
  assert_eq(z, T32_QUARTER)
}
