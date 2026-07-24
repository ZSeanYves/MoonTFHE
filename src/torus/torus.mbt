///|
/// A value in the 32-bit torus Z/(2^32)Z.
pub struct Torus32 {
  raw : Int
} derive(Debug, Eq)

///|
pub suberror ModulusError {
  InvalidLogModulus
  ValueOutOfRange
} derive(Debug, Eq)

///|
pub enum CiphertextModulus {
  Torus32Modulus
  PowerOfTwo(Int)
} derive(Debug, Eq)

///|
pub fn Torus32::from_int(raw : Int) -> Torus32 {
  { raw, }
}

///|
pub fn Torus32::to_int(self : Torus32) -> Int {
  self.raw
}

///|
pub fn Torus32::zero() -> Torus32 {
  { raw: 0 }
}

///|
pub fn Torus32::add(self : Torus32, other : Torus32) -> Torus32 {
  { raw: self.raw + other.raw }
}

///|
pub fn Torus32::sub(self : Torus32, other : Torus32) -> Torus32 {
  { raw: self.raw - other.raw }
}

///|
pub fn Torus32::neg(self : Torus32) -> Torus32 {
  { raw: -self.raw }
}

///|
pub fn Torus32::scale(self : Torus32, scalar : Int) -> Torus32 {
  { raw: self.raw * scalar }
}

///|
pub fn Torus32::encode_bit_pm(message : Bool, amplitude : Torus32) -> Torus32 {
  if message {
    amplitude
  } else {
    amplitude.neg()
  }
}

///|
pub fn Torus32::decode_sign(self : Torus32) -> Bool {
  self.raw >= 0
}

///|
pub fn CiphertextModulus::power_of_two(
  log_modulus : Int,
) -> Result[CiphertextModulus, ModulusError] {
  if log_modulus <= 0 || log_modulus > 16 {
    Err(InvalidLogModulus)
  } else {
    Ok(PowerOfTwo(log_modulus))
  }
}

///|
pub fn Torus32::modulus_switch(
  self : Torus32,
  modulus : CiphertextModulus,
) -> Result[Int, ModulusError] {
  match modulus {
    Torus32Modulus => Ok(self.raw)
    PowerOfTwo(log_modulus) => {
      if log_modulus <= 0 || log_modulus > 16 {
        return Err(InvalidLogModulus)
      }
      let q : Int64 = 1L << log_modulus
      let unsigned = self.raw.reinterpret_as_uint().to_int64()
      Ok((((unsigned * q + 0x8000_0000L) >> 32) % q).to_int())
    }
  }
}

///|
pub fn torus_from_modulus(
  value : Int,
  modulus : CiphertextModulus,
) -> Result[Torus32, ModulusError] {
  match modulus {
    Torus32Modulus => Ok(Torus32::from_int(value))
    PowerOfTwo(log_modulus) => {
      if log_modulus <= 0 || log_modulus > 16 {
        return Err(InvalidLogModulus)
      }
      let q = 1L << log_modulus
      if value < 0 || value.to_int64() >= q {
        return Err(ValueOutOfRange)
      }
      Ok(
        Torus32::from_int(
          (value.to_int64() << (32 - log_modulus))
          .reinterpret_as_uint64()
          .to_uint()
          .reinterpret_as_int(),
        ),
      )
    }
  }
}

///|
test "torus32: arithmetic wraps and preserves sign encoding" {
  let max = Torus32::from_int(0xFFFF_FFFF)
  assert_eq(max.add(Torus32::from_int(2)).to_int(), 1)
  let amplitude = Torus32::from_int(0x2000_0000)
  assert_true(Torus32::encode_bit_pm(true, amplitude).decode_sign())
  assert_true(!Torus32::encode_bit_pm(false, amplitude).decode_sign())
}

///|
test "torus32: modulus switching round trips powers of two" {
  assert_eq(Torus32::from_int(-1).modulus_switch(Torus32Modulus).unwrap(), -1)
  for log_modulus in 1..<=8 {
    let modulus = CiphertextModulus::power_of_two(log_modulus).unwrap()
    let q = 1 << log_modulus
    for value in 0..<q {
      let torus = torus_from_modulus(value, modulus).unwrap()
      assert_eq(torus.modulus_switch(modulus).unwrap(), value)
    }
  }
}
