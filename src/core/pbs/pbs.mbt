///|
pub enum PbsOrder {
  KeyswitchBootstrap
  BootstrapKeyswitch
} derive(Debug, Eq)

///|
/// A fixed two-point Boolean programmable LUT. The full arbitrary torus LUT
/// representation is added with the Fourier BSK backend in C4.
pub struct BooleanLut {
  false_value : @torus.Torus32
  true_value : @torus.Torus32
} derive(Debug, Eq)

///|
pub suberror PbsError {
  InvalidLut
} derive(Debug, Eq)

///|
pub fn boolean_lut(
  false_value : @torus.Torus32,
  true_value : @torus.Torus32,
) -> BooleanLut {
  { false_value, true_value }
}

///|
pub fn BooleanLut::evaluate_reference(
  self : BooleanLut,
  input : Bool,
) -> @torus.Torus32 {
  if input {
    self.true_value
  } else {
    self.false_value
  }
}

///|
pub fn BooleanLut::false_value(self : BooleanLut) -> @torus.Torus32 {
  self.false_value
}

///|
pub fn BooleanLut::true_value(self : BooleanLut) -> @torus.Torus32 {
  self.true_value
}

///|
test "pbs: Boolean LUT reference preserves both torus outputs" {
  let lut = boolean_lut(
    @torus.Torus32::from_int(-0x2000_0000),
    @torus.Torus32::from_int(0x2000_0000),
  )
  assert_eq(lut.evaluate_reference(false).to_int(), -0x2000_0000)
  assert_eq(lut.evaluate_reference(true).to_int(), 0x2000_0000)
}
