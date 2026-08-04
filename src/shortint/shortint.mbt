///|
pub suberror ShortintError {
  InvalidModulus
  InvalidMessage
  InvalidCiphertext
  KeyMismatch
  BooleanFailure
} derive(Debug, Eq)

///|
/// A message modulus and carry modulus for the first Shortint facade.
///
/// The current implementation uses Boolean bit blocks and therefore requires
/// power-of-two message moduli.  Carry metadata is retained explicitly so the
/// representation can be replaced by a native shortint encoding without
/// changing callers.
pub struct ShortintParameters {
  priv boolean_parameters : @boolean.BooleanParameters
  priv message_modulus : UInt
  priv carry_modulus : UInt
  priv block_count : Int
}

///|
pub struct Degree {
  priv value : UInt
}

///|
pub fn Degree::value(self : Degree) -> UInt {
  self.value
}

///|
pub struct NoiseLevel {
  priv value : UInt
}

///|
pub fn NoiseLevel::value(self : NoiseLevel) -> UInt {
  self.value
}

///|
/// Opaque shortint ciphertext represented by Boolean blocks, least significant
/// block first.
pub struct ShortintCiphertext {
  priv blocks : Array[@boolean.Ciphertext]
  priv parameters : ShortintParameters
  priv degree : Degree
  priv noise : NoiseLevel
}

///|
pub struct ShortintClientKey {
  priv inner : @boolean.ClientKey
  priv parameters : ShortintParameters
}

///|
pub struct ShortintServerKey {
  priv inner : @boolean.ServerKey
  priv parameters : ShortintParameters
}

///|
priv enum BitwiseOp {
  BitAnd
  BitOr
  BitXor
}

///|
fn bit_width(modulus : UInt) -> Int {
  let mut value = modulus - 1U
  let mut width = 0
  while value > 0U {
    value = value >> 1
    width = width + 1
  }
  width
}

///|
fn is_power_of_two(value : UInt) -> Bool {
  value > 1U && (value & (value - 1U)) == 0U
}

///|
fn parameters_match(
  left : ShortintParameters,
  right : ShortintParameters,
) -> Bool {
  left.boolean_parameters.id() == right.boolean_parameters.id() &&
  left.message_modulus == right.message_modulus &&
  left.carry_modulus == right.carry_modulus &&
  left.block_count == right.block_count
}

///|
pub fn shortint_parameters(
  boolean_parameters : @boolean.BooleanParameters,
  message_modulus : UInt,
  carry_modulus : UInt,
) -> Result[ShortintParameters, ShortintError] {
  if !is_power_of_two(message_modulus) || !is_power_of_two(carry_modulus) {
    return Err(InvalidModulus)
  }
  let block_count = bit_width(message_modulus)
  if block_count <= 0 || block_count > 16 {
    return Err(InvalidModulus)
  }
  Ok({ boolean_parameters, message_modulus, carry_modulus, block_count })
}

///|
pub fn ShortintParameters::message_modulus(self : ShortintParameters) -> UInt {
  self.message_modulus
}

///|
pub fn ShortintParameters::parameter_id(self : ShortintParameters) -> String {
  self.boolean_parameters.id()
}

///|
pub fn ShortintParameters::carry_modulus(self : ShortintParameters) -> UInt {
  self.carry_modulus
}

///|
pub fn ShortintParameters::block_count(self : ShortintParameters) -> Int {
  self.block_count
}

///|
pub fn generate_keys(
  parameters : ShortintParameters,
) -> Result[(ShortintClientKey, ShortintServerKey), ShortintError] {
  match @boolean.generate_keys(parameters.boolean_parameters) {
    Ok((client, server)) =>
      Ok(({ inner: client, parameters }, { inner: server, parameters }))
    Err(_) => Err(BooleanFailure)
  }
}

///|
/// Deterministic constructor used only by unit tests and reference examples.
pub fn generate_test_keys(
  parameters : ShortintParameters,
  seed : UInt64,
) -> Result[(ShortintClientKey, ShortintServerKey), ShortintError] {
  match @boolean.generate_test_keys(parameters.boolean_parameters, seed) {
    Ok((client, server)) =>
      Ok(({ inner: client, parameters }, { inner: server, parameters }))
    Err(_) => Err(BooleanFailure)
  }
}

///|
pub fn ShortintClientKey::encrypt(
  self : ShortintClientKey,
  message : UInt,
) -> Result[ShortintCiphertext, ShortintError] {
  if message >= self.parameters.message_modulus {
    return Err(InvalidMessage)
  }
  let blocks : Array[@boolean.Ciphertext] = []
  for index in 0..<self.parameters.block_count {
    blocks.push(self.inner.encrypt(((message >> index) & 1U) == 1U))
  }
  Ok({
    blocks,
    parameters: self.parameters,
    degree: { value: message },
    noise: { value: 1U },
  })
}

///|
pub fn ShortintClientKey::decrypt(
  self : ShortintClientKey,
  ciphertext : ShortintCiphertext,
) -> Result[UInt, ShortintError] {
  if !parameters_match(ciphertext.parameters, self.parameters) ||
    ciphertext.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let mut result = 0U
  for index in 0..<ciphertext.blocks.length() {
    match self.inner.decrypt(ciphertext.blocks[index]) {
      Ok(true) => result = result | (1U << index)
      Ok(false) => ()
      Err(_) => return Err(InvalidCiphertext)
    }
  }
  Ok(result)
}

///|
pub fn ShortintCiphertext::degree(self : ShortintCiphertext) -> Degree {
  self.degree
}

///|
pub fn ShortintCiphertext::noise_level(self : ShortintCiphertext) -> NoiseLevel {
  self.noise
}

///|
fn gate_xor(
  server : @boolean.ServerKey,
  left : @boolean.Ciphertext,
  right : @boolean.Ciphertext,
) -> Result[@boolean.Ciphertext, ShortintError] {
  match server.xor_gate(left, right) {
    Ok(value) => Ok(value)
    Err(_) => Err(BooleanFailure)
  }
}

///|
fn gate_and(
  server : @boolean.ServerKey,
  left : @boolean.Ciphertext,
  right : @boolean.Ciphertext,
) -> Result[@boolean.Ciphertext, ShortintError] {
  match server.and_gate(left, right) {
    Ok(value) => Ok(value)
    Err(_) => Err(BooleanFailure)
  }
}

///|
fn gate_or(
  server : @boolean.ServerKey,
  left : @boolean.Ciphertext,
  right : @boolean.Ciphertext,
) -> Result[@boolean.Ciphertext, ShortintError] {
  match server.or_gate(left, right) {
    Ok(value) => Ok(value)
    Err(_) => Err(BooleanFailure)
  }
}

///|
fn apply_bitwise(
  server : @boolean.ServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
  parameters : ShortintParameters,
  operation : BitwiseOp,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(left.parameters, parameters) ||
    !parameters_match(right.parameters, parameters) ||
    left.blocks.length() != parameters.block_count ||
    right.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  let result : Array[@boolean.Ciphertext] = []
  for index in 0..<parameters.block_count {
    let block = match operation {
      BitAnd => gate_and(server, left.blocks[index], right.blocks[index])
      BitOr => gate_or(server, left.blocks[index], right.blocks[index])
      BitXor => gate_xor(server, left.blocks[index], right.blocks[index])
    }
    match block {
      Ok(value) => result.push(value)
      Err(error) => return Err(error)
    }
  }
  Ok({
    blocks: result,
    parameters,
    degree: { value: parameters.message_modulus - 1U },
    noise: { value: left.noise.value + right.noise.value + 1U },
  })
}

///|
pub fn ShortintServerKey::add_with_carry(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[(ShortintCiphertext, ShortintCiphertext), ShortintError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match gate_xor(self.inner, left.blocks[0], left.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let mut carry = zero
  let result : Array[@boolean.Ciphertext] = []
  for index in 0..<self.parameters.block_count {
    let a = left.blocks[index]
    let b = right.blocks[index]
    let partial = match gate_xor(self.inner, a, b) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let sum = match gate_xor(self.inner, partial, carry) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let ab = match gate_and(self.inner, a, b) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let carry_partial = match gate_and(self.inner, partial, carry) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    carry = match gate_or(self.inner, ab, carry_partial) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    result.push(sum)
  }
  let output = {
    blocks: result,
    parameters: self.parameters,
    degree: { value: self.parameters.message_modulus - 1U },
    noise: { value: left.noise.value + right.noise.value + 1U },
  }
  let carry_blocks : Array[@boolean.Ciphertext] = [carry]
  for _ in 1..<self.parameters.block_count {
    carry_blocks.push(zero)
  }
  Ok(
    (
      output,
      {
        blocks: carry_blocks,
        parameters: self.parameters,
        degree: { value: 1U },
        noise: { value: left.noise.value + right.noise.value + 1U },
      },
    ),
  )
}

///|
pub fn ShortintServerKey::unchecked_add(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  match self.add_with_carry(left, right) {
    Ok((result, _carry)) => Ok(result)
    Err(error) => Err(error)
  }
}

///|
pub fn ShortintServerKey::add(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  self.unchecked_add(left, right)
}

///|
/// The Boolean-block research backend refreshes every gate, so smart and
/// default addition currently share the same carry-normalized implementation.
pub fn ShortintServerKey::smart_add(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  self.unchecked_add(left, right)
}

///|
pub fn ShortintServerKey::sub_with_borrow(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[(ShortintCiphertext, ShortintCiphertext), ShortintError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match gate_xor(self.inner, left.blocks[0], left.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let mut borrow = zero
  let result : Array[@boolean.Ciphertext] = []
  for index in 0..<self.parameters.block_count {
    let a = left.blocks[index]
    let b = right.blocks[index]
    let partial = match gate_xor(self.inner, a, b) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let difference = match gate_xor(self.inner, partial, borrow) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let not_a = match self.inner.not(a) {
      Ok(value) => value
      Err(_) => return Err(BooleanFailure)
    }
    let first = match gate_and(self.inner, not_a, b) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let second = match gate_and(self.inner, not_a, borrow) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let third = match gate_and(self.inner, b, borrow) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let partial_borrow = match gate_or(self.inner, first, second) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    borrow = match gate_or(self.inner, partial_borrow, third) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    result.push(difference)
  }
  let output = {
    blocks: result,
    parameters: self.parameters,
    degree: { value: self.parameters.message_modulus - 1U },
    noise: { value: left.noise.value + right.noise.value + 1U },
  }
  let borrow_blocks : Array[@boolean.Ciphertext] = [borrow]
  for _ in 1..<self.parameters.block_count {
    borrow_blocks.push(zero)
  }
  Ok(
    (
      output,
      {
        blocks: borrow_blocks,
        parameters: self.parameters,
        degree: { value: 1U },
        noise: { value: left.noise.value + right.noise.value + 1U },
      },
    ),
  )
}

///|
pub fn ShortintServerKey::unchecked_sub(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  match self.sub_with_borrow(left, right) {
    Ok((result, _borrow)) => Ok(result)
    Err(error) => Err(error)
  }
}

///|
pub fn ShortintServerKey::bitand(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  apply_bitwise(self.inner, left, right, self.parameters, BitAnd)
}

///|
pub fn ShortintServerKey::bitor(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  apply_bitwise(self.inner, left, right, self.parameters, BitOr)
}

///|
pub fn ShortintServerKey::bitxor(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  apply_bitwise(self.inner, left, right, self.parameters, BitXor)
}

///|
pub fn ShortintServerKey::bitnot(
  self : ShortintServerKey,
  input : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(input.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let blocks : Array[@boolean.Ciphertext] = []
  for block in input.blocks {
    match self.inner.not(block) {
      Ok(value) => blocks.push(value)
      Err(_) => return Err(BooleanFailure)
    }
  }
  Ok({
    blocks,
    parameters: self.parameters,
    degree: { value: self.parameters.message_modulus - 1U },
    noise: { value: input.noise.value + 1U },
  })
}

///|
pub fn ShortintServerKey::scalar_add(
  self : ShortintServerKey,
  input : ShortintCiphertext,
  scalar : UInt,
) -> Result[ShortintCiphertext, ShortintError] {
  match self.scalar_add_with_carry(input, scalar) {
    Ok((result, _carry)) => Ok(result)
    Err(error) => Err(error)
  }
}

///|
/// Adds a plaintext scalar and returns the carry as a one-bit shortint block.
/// This is a research-layer primitive used by the radix integer facade; the
/// result is reduced modulo the message modulus.
pub fn ShortintServerKey::scalar_add_with_carry(
  self : ShortintServerKey,
  input : ShortintCiphertext,
  scalar : UInt,
) -> Result[(ShortintCiphertext, ShortintCiphertext), ShortintError] {
  if scalar >= self.parameters.message_modulus {
    return Err(InvalidMessage)
  }
  if !parameters_match(input.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match gate_xor(self.inner, input.blocks[0], input.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let one = match self.inner.xnor_gate(zero, zero) {
    Ok(value) => value
    Err(_) => return Err(BooleanFailure)
  }
  let scalar_blocks : Array[@boolean.Ciphertext] = []
  for index in 0..<self.parameters.block_count {
    scalar_blocks.push(if ((scalar >> index) & 1U) == 1U { one } else { zero })
  }
  let scalar_cipher = {
    blocks: scalar_blocks,
    parameters: self.parameters,
    degree: { value: scalar },
    noise: { value: 1U },
  }
  self.add_with_carry(input, scalar_cipher)
}

///|
fn shortint_constant_like(
  server : @boolean.ServerKey,
  input : ShortintCiphertext,
  parameters : ShortintParameters,
  value : UInt,
) -> Result[ShortintCiphertext, ShortintError] {
  if value >= parameters.message_modulus ||
    !parameters_match(input.parameters, parameters) ||
    input.blocks.length() != parameters.block_count {
    return Err(InvalidMessage)
  }
  let zero = match gate_xor(server, input.blocks[0], input.blocks[0]) {
    Ok(ciphertext) => ciphertext
    Err(error) => return Err(error)
  }
  let one = match server.xnor_gate(zero, zero) {
    Ok(ciphertext) => ciphertext
    Err(_) => return Err(BooleanFailure)
  }
  let blocks : Array[@boolean.Ciphertext] = []
  for index in 0..<parameters.block_count {
    blocks.push(if ((value >> index) & 1U) == 1U { one } else { zero })
  }
  Ok({ blocks, parameters, degree: { value, }, noise: { value: 1U } })
}

///|
/// Returns one encrypted bit in the least-significant position.
pub fn ShortintServerKey::bit_at(
  self : ShortintServerKey,
  input : ShortintCiphertext,
  index : Int,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(input.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  if index < 0 || index >= self.parameters.block_count {
    return Err(InvalidMessage)
  }
  let zero = match gate_xor(self.inner, input.blocks[0], input.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let blocks : Array[@boolean.Ciphertext] = [input.blocks[index]]
  for _ in 1..<self.parameters.block_count {
    blocks.push(zero)
  }
  Ok({
    blocks,
    parameters: self.parameters,
    degree: { value: 1U },
    noise: { value: input.noise.value + 1U },
  })
}

///|
/// Selects between two shortint ciphertexts using the selector's low bit.
pub fn ShortintServerKey::select(
  self : ShortintServerKey,
  selector : ShortintCiphertext,
  when_true : ShortintCiphertext,
  when_false : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(selector.parameters, self.parameters) ||
    !parameters_match(when_true.parameters, self.parameters) ||
    !parameters_match(when_false.parameters, self.parameters) ||
    selector.blocks.length() != self.parameters.block_count ||
    when_true.blocks.length() != self.parameters.block_count ||
    when_false.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let blocks : Array[@boolean.Ciphertext] = []
  for index in 0..<self.parameters.block_count {
    match
      self.inner.mux(
        selector.blocks[0],
        when_true.blocks[index],
        when_false.blocks[index],
      ) {
      Ok(value) => blocks.push(value)
      Err(_) => return Err(BooleanFailure)
    }
  }
  Ok({
    blocks,
    parameters: self.parameters,
    degree: {
      value: if when_true.degree.value > when_false.degree.value {
        when_true.degree.value
      } else {
        when_false.degree.value
      },
    },
    noise: {
      value: selector.noise.value +
      when_true.noise.value +
      when_false.noise.value +
      1U,
    },
  })
}

///|
/// Returns an encrypted one when both shortint values are equal.
pub fn ShortintServerKey::equal(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let mut equal = match self.inner.xnor_gate(left.blocks[0], right.blocks[0]) {
    Ok(value) => value
    Err(_) => return Err(BooleanFailure)
  }
  for index in 1..<self.parameters.block_count {
    let bit_equal = match
      self.inner.xnor_gate(left.blocks[index], right.blocks[index]) {
      Ok(value) => value
      Err(_) => return Err(BooleanFailure)
    }
    equal = match gate_and(self.inner, equal, bit_equal) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
  }
  let zero = match gate_xor(self.inner, equal, equal) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let blocks : Array[@boolean.Ciphertext] = [equal]
  for _ in 1..<self.parameters.block_count {
    blocks.push(zero)
  }
  Ok({
    blocks,
    parameters: self.parameters,
    degree: { value: 1U },
    noise: { value: left.noise.value + right.noise.value + 1U },
  })
}

///|
/// Unsigned encrypted comparison.
pub fn ShortintServerKey::less_than(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match gate_xor(self.inner, left.blocks[0], left.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let mut less = zero
  let mut equal = match self.inner.xnor_gate(zero, zero) {
    Ok(value) => value
    Err(_) => return Err(BooleanFailure)
  }
  let mut index = self.parameters.block_count - 1
  while index >= 0 {
    let not_left = match self.inner.not(left.blocks[index]) {
      Ok(value) => value
      Err(_) => return Err(BooleanFailure)
    }
    let bit_less = match gate_and(self.inner, not_left, right.blocks[index]) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let decisive = match gate_and(self.inner, equal, bit_less) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    less = match gate_or(self.inner, less, decisive) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let bit_equal = match
      self.inner.xnor_gate(left.blocks[index], right.blocks[index]) {
      Ok(value) => value
      Err(_) => return Err(BooleanFailure)
    }
    equal = match gate_and(self.inner, equal, bit_equal) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    index = index - 1
  }
  let blocks : Array[@boolean.Ciphertext] = [less]
  for _ in 1..<self.parameters.block_count {
    blocks.push(zero)
  }
  Ok({
    blocks,
    parameters: self.parameters,
    degree: { value: 1U },
    noise: { value: left.noise.value + right.noise.value + 1U },
  })
}

///|
/// Shifts one bit left, inserting the low bit of `incoming`, and returns the
/// discarded high bit as a one-bit shortint value.
pub fn ShortintServerKey::shift_left_one(
  self : ShortintServerKey,
  input : ShortintCiphertext,
  incoming : ShortintCiphertext,
) -> Result[(ShortintCiphertext, ShortintCiphertext), ShortintError] {
  if !parameters_match(input.parameters, self.parameters) ||
    !parameters_match(incoming.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count ||
    incoming.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match gate_xor(self.inner, input.blocks[0], input.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let blocks : Array[@boolean.Ciphertext] = [incoming.blocks[0]]
  for index in 1..<self.parameters.block_count {
    blocks.push(input.blocks[index - 1])
  }
  let carry_blocks : Array[@boolean.Ciphertext] = [
    input.blocks[self.parameters.block_count - 1],
  ]
  for _ in 1..<self.parameters.block_count {
    carry_blocks.push(zero)
  }
  Ok(
    (
      {
        blocks,
        parameters: self.parameters,
        degree: { value: self.parameters.message_modulus - 1U },
        noise: { value: input.noise.value + incoming.noise.value },
      },
      {
        blocks: carry_blocks,
        parameters: self.parameters,
        degree: { value: 1U },
        noise: input.noise,
      },
    ),
  )
}

///|
/// Shifts one bit right, inserting the low bit of `incoming` at the high end.
pub fn ShortintServerKey::shift_right_one(
  self : ShortintServerKey,
  input : ShortintCiphertext,
  incoming : ShortintCiphertext,
) -> Result[(ShortintCiphertext, ShortintCiphertext), ShortintError] {
  if !parameters_match(input.parameters, self.parameters) ||
    !parameters_match(incoming.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count ||
    incoming.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match gate_xor(self.inner, input.blocks[0], input.blocks[0]) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let blocks : Array[@boolean.Ciphertext] = []
  for index in 0..<(self.parameters.block_count - 1) {
    blocks.push(input.blocks[index + 1])
  }
  blocks.push(incoming.blocks[0])
  let carry_blocks : Array[@boolean.Ciphertext] = [input.blocks[0]]
  for _ in 1..<self.parameters.block_count {
    carry_blocks.push(zero)
  }
  Ok(
    (
      {
        blocks,
        parameters: self.parameters,
        degree: { value: self.parameters.message_modulus - 1U },
        noise: { value: input.noise.value + incoming.noise.value },
      },
      {
        blocks: carry_blocks,
        parameters: self.parameters,
        degree: { value: 1U },
        noise: input.noise,
      },
    ),
  )
}

///|
/// Multiplies two shortint values modulo the message modulus.
pub fn ShortintServerKey::mul(
  self : ShortintServerKey,
  left : ShortintCiphertext,
  right : ShortintCiphertext,
) -> Result[ShortintCiphertext, ShortintError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let mut result = match
    shortint_constant_like(self.inner, left, self.parameters, 0U) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let zero = result.blocks[0]
  for multiplier_bit in 0..<self.parameters.block_count {
    let partial_blocks : Array[@boolean.Ciphertext] = []
    for output_bit in 0..<self.parameters.block_count {
      if output_bit < multiplier_bit {
        partial_blocks.push(zero)
      } else {
        match
          gate_and(
            self.inner,
            left.blocks[output_bit - multiplier_bit],
            right.blocks[multiplier_bit],
          ) {
          Ok(value) => partial_blocks.push(value)
          Err(error) => return Err(error)
        }
      }
    }
    let partial = {
      blocks: partial_blocks,
      parameters: self.parameters,
      degree: { value: self.parameters.message_modulus - 1U },
      noise: { value: left.noise.value + right.noise.value + 1U },
    }
    result = match self.unchecked_add(result, partial) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn ShortintServerKey::scalar_mul(
  self : ShortintServerKey,
  input : ShortintCiphertext,
  scalar : UInt,
) -> Result[ShortintCiphertext, ShortintError] {
  let constant = match
    shortint_constant_like(self.inner, input, self.parameters, scalar) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  self.mul(input, constant)
}
