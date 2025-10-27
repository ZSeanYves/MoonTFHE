// Torus Q1.31 based on Int (32-bit). 通过 Int 自然溢出实现 mod 2^32。
// 0.5 in Q1.31，用作布尔阈值
pub const T32_HALF : Int = 0x8000_0000

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
///|
pub fn t32_to_bool(mu : Int) -> Bool {
  mu < T32_HALF
}

// 将任意浮点 x 映射到 [0,1) 再编码到 Q1.31
///|
pub fn f64_to_t32(x : Float) -> Int {
  let frac01 = if x >= 0.0 {
    let xi : Int = x.to_int() 
    x - xi.to_float() // frac in [0,1)
  } else {
    let a : Float = -x
    let ai : Int = a.to_int()
    let af : Float = a - ai.to_float() 
    if af == 0.0 {
      0.0
    } else {
      1.0 - af
    } 
  }
  (frac01 * 4294967296.0).to_int() 
}
