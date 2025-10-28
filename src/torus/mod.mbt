// Torus Q1.31 based on Int (32-bit). 通过 Int 自然溢出实现 mod 2^32。
// 0.5 in Q1.31，用作布尔阈值
///|
pub const T32_HALF : Int = 0x8000_0000
// 额外常量：0.25 in Q1.31
///|
pub const T32_QUARTER : Int = 0x4000_0000

// 基本运算（自然溢出即模 2^32）
///|
pub fn t32_add(a : Int, b : Int) -> Int {
  a + b
}
///|
pub fn t32_sub(a : Int, b : Int) -> Int {
  a - b
}
///|
pub fn t32_mul_k(a : Int, k : Int) -> Int {
  a * k
}

// 布尔相位编码：true -> 0，false -> 0.5
///|
pub fn bool_to_t32(b : Bool) -> Int {
  if b {
    0x0000_0000
  } else {
    T32_HALF
  }
}

// 相位阈值：小于 0.5 视为 true
// 直接用符号位判定（非负 => [0,0.5) => true；负数 => [0.5,1) => false）
///|
pub fn t32_to_bool(mu : Int) -> Bool {
  mu >= 0
}

// 对称编码：true -> +mu, false -> -mu  （mu 建议取 T32_QUARTER）
///|
pub fn t32_encode_bit_pm(b : Bool, mu : Int) -> Int {
  if b {
    mu
  } else {
    -mu
  }
}

// 对称解码：看符号位（>=0 为 true）
///|
pub fn t32_decode_sign(x : Int) -> Bool {
  x >= 0
}

// 将任意浮点 x 映射到 [0,1) 再编码到 Q1.31（避免 2^31 溢出/饱和）
///|
pub fn f64_to_t32(x : Float) -> Int {
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
