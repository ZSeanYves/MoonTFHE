///|
pub suberror IntegerError {
  InvalidBlockCount
  InvalidValue
  InvalidShift
  KeyMismatch
  SignedOperationUnsupported
  ShortintFailure
} derive(Debug, Eq)

///|
pub struct IntegerParameters {
  priv shortint : @shortint.ShortintParameters
  priv block_count : Int
  priv signed : Bool
}

///|
pub struct IntegerCiphertext {
  priv blocks : Array[@shortint.ShortintCiphertext]
  priv parameters : IntegerParameters
}

///|
pub struct IntegerClientKey {
  priv inner : @shortint.ShortintClientKey
  priv parameters : IntegerParameters
}

///|
pub struct IntegerServerKey {
  priv inner : @shortint.ShortintServerKey
  priv parameters : IntegerParameters
}

///|
/// An encrypted Boolean produced by integer comparisons.
pub struct BooleanBlock {
  priv inner : @shortint.ShortintCiphertext
  priv parameters : IntegerParameters
}

///|
priv enum IntegerBitwiseOp {
  And
  Or
  Xor
}

///|
pub fn integer_parameters(
  boolean_parameters : @boolean.BooleanParameters,
  block_count : Int,
  signed : Bool,
) -> Result[IntegerParameters, IntegerError] {
  if block_count <= 0 || block_count > 16 {
    return Err(InvalidBlockCount)
  }
  match @shortint.shortint_parameters(boolean_parameters, 16U, 4U) {
    Ok(shortint) => Ok({ shortint, block_count, signed })
    Err(_) => Err(ShortintFailure)
  }
}

///|
pub fn IntegerParameters::block_count(self : IntegerParameters) -> Int {
  self.block_count
}

///|
pub fn IntegerParameters::is_signed(self : IntegerParameters) -> Bool {
  self.signed
}

///|
fn parameters_match(
  left : IntegerParameters,
  right : IntegerParameters,
) -> Bool {
  left.block_count == right.block_count &&
  left.signed == right.signed &&
  left.shortint.parameter_id() == right.shortint.parameter_id() &&
  left.shortint.message_modulus() == right.shortint.message_modulus() &&
  left.shortint.carry_modulus() == right.shortint.carry_modulus() &&
  left.shortint.block_count() == right.shortint.block_count() &&
  left.shortint.block_count() > 0
}

///|
pub fn generate_test_keys(
  parameters : IntegerParameters,
  seed : UInt64,
) -> Result[(IntegerClientKey, IntegerServerKey), IntegerError] {
  match @shortint.generate_test_keys(parameters.shortint, seed) {
    Ok((client, server)) =>
      Ok(({ inner: client, parameters }, { inner: server, parameters }))
    Err(_) => Err(ShortintFailure)
  }
}

///|
pub fn generate_keys(
  parameters : IntegerParameters,
) -> Result[(IntegerClientKey, IntegerServerKey), IntegerError] {
  match @shortint.generate_keys(parameters.shortint) {
    Ok((client, server)) =>
      Ok(({ inner: client, parameters }, { inner: server, parameters }))
    Err(_) => Err(ShortintFailure)
  }
}

///|
pub fn IntegerClientKey::encrypt(
  self : IntegerClientKey,
  value : UInt64,
) -> Result[IntegerCiphertext, IntegerError] {
  let bits = self.parameters.block_count * 4
  if bits < 64 && value >= 1UL << bits {
    return Err(InvalidValue)
  }
  let blocks : Array[@shortint.ShortintCiphertext] = []
  let mut remaining = value
  for _ in 0..<self.parameters.block_count {
    let block = (remaining & 0xFUL).to_uint()
    match self.inner.encrypt(block) {
      Ok(ciphertext) => blocks.push(ciphertext)
      Err(_) => return Err(ShortintFailure)
    }
    remaining = remaining >> 4
  }
  Ok({ blocks, parameters: self.parameters })
}

///|
pub fn IntegerClientKey::decrypt(
  self : IntegerClientKey,
  ciphertext : IntegerCiphertext,
) -> Result[UInt64, IntegerError] {
  if !parameters_match(ciphertext.parameters, self.parameters) ||
    ciphertext.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let mut result = 0UL
  for index in 0..<ciphertext.blocks.length() {
    match self.inner.decrypt(ciphertext.blocks[index]) {
      Ok(value) => result = result | (value.to_uint64() << (index * 4))
      Err(_) => return Err(ShortintFailure)
    }
  }
  Ok(result)
}

///|
pub fn IntegerClientKey::decrypt_bool(
  self : IntegerClientKey,
  value : BooleanBlock,
) -> Result[Bool, IntegerError] {
  if !parameters_match(value.parameters, self.parameters) {
    return Err(KeyMismatch)
  }
  match self.inner.decrypt(value.inner) {
    Ok(result) => Ok((result & 1U) == 1U)
    Err(_) => Err(ShortintFailure)
  }
}

///|
fn integer_zero_like(
  server : @shortint.ShortintServerKey,
  input : IntegerCiphertext,
  parameters : IntegerParameters,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(input.parameters, parameters) ||
    input.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match server.scalar_add_with_carry(input.blocks[0], 0U) {
    Ok((_unchanged, carry)) => carry
    Err(_) => return Err(ShortintFailure)
  }
  Ok({ blocks: Array::make(parameters.block_count, zero), parameters })
}

///|
fn integer_bit_at(
  server : @shortint.ShortintServerKey,
  input : IntegerCiphertext,
  parameters : IntegerParameters,
  index : Int,
) -> Result[BooleanBlock, IntegerError] {
  let width = parameters.block_count * 4
  if !parameters_match(input.parameters, parameters) ||
    input.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  if index < 0 || index >= width {
    return Err(InvalidShift)
  }
  match server.bit_at(input.blocks[index / 4], index % 4) {
    Ok(inner) => Ok({ inner, parameters })
    Err(_) => Err(ShortintFailure)
  }
}

///|
fn shift_left_one_internal(
  server : @shortint.ShortintServerKey,
  input : IntegerCiphertext,
  incoming : @shortint.ShortintCiphertext,
  parameters : IntegerParameters,
) -> Result[(IntegerCiphertext, @shortint.ShortintCiphertext), IntegerError] {
  if !parameters_match(input.parameters, parameters) ||
    input.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  let result : Array[@shortint.ShortintCiphertext] = []
  let mut carry = incoming
  for index in 0..<parameters.block_count {
    let (shifted, outgoing) = match
      server.shift_left_one(input.blocks[index], carry) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    result.push(shifted)
    carry = outgoing
  }
  Ok(({ blocks: result, parameters }, carry))
}

///|
fn shift_right_one_internal(
  server : @shortint.ShortintServerKey,
  input : IntegerCiphertext,
  incoming : @shortint.ShortintCiphertext,
  parameters : IntegerParameters,
) -> Result[(IntegerCiphertext, @shortint.ShortintCiphertext), IntegerError] {
  if !parameters_match(input.parameters, parameters) ||
    input.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  let result = Array::make(parameters.block_count, input.blocks[0])
  let mut carry = incoming
  let mut index = parameters.block_count - 1
  while index >= 0 {
    let (shifted, outgoing) = match
      server.shift_right_one(input.blocks[index], carry) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    result[index] = shifted
    carry = outgoing
    index = index - 1
  }
  Ok(({ blocks: result, parameters }, carry))
}

///|
pub fn IntegerServerKey::add(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let result : Array[@shortint.ShortintCiphertext] = []
  let mut carry = match
    self.inner.add_with_carry(left.blocks[0], right.blocks[0]) {
    Ok((sum, next)) => {
      result.push(sum)
      next
    }
    Err(_) => return Err(ShortintFailure)
  }
  for index in 1..<self.parameters.block_count {
    let with_carry = match
      self.inner.add_with_carry(left.blocks[index], carry) {
      Ok((partial, next_carry)) =>
        match self.inner.add_with_carry(partial, right.blocks[index]) {
          Ok((sum, final_carry)) => {
            result.push(sum)
            match self.inner.bitor(next_carry, final_carry) {
              Ok(combined) => combined
              Err(_) => return Err(ShortintFailure)
            }
          }
          Err(_) => return Err(ShortintFailure)
        }
      Err(_) => return Err(ShortintFailure)
    }
    carry = with_carry
  }
  Ok({ blocks: result, parameters: self.parameters })
}

///|
pub fn IntegerServerKey::sub(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let result : Array[@shortint.ShortintCiphertext] = []
  let mut borrow = match
    self.inner.sub_with_borrow(left.blocks[0], right.blocks[0]) {
    Ok((difference, next)) => {
      result.push(difference)
      next
    }
    Err(_) => return Err(ShortintFailure)
  }
  for index in 1..<self.parameters.block_count {
    let with_borrow = match
      self.inner.sub_with_borrow(left.blocks[index], borrow) {
      Ok((partial, next_borrow)) =>
        match self.inner.sub_with_borrow(partial, right.blocks[index]) {
          Ok((difference, final_borrow)) => {
            result.push(difference)
            match self.inner.bitor(next_borrow, final_borrow) {
              Ok(combined) => combined
              Err(_) => return Err(ShortintFailure)
            }
          }
          Err(_) => return Err(ShortintFailure)
        }
      Err(_) => return Err(ShortintFailure)
    }
    borrow = with_borrow
  }
  Ok({ blocks: result, parameters: self.parameters })
}

///|
/// Adds a plaintext scalar to a radix ciphertext.  Arithmetic is performed
/// modulo the configured integer width and carries are propagated between
/// radix blocks without exposing a client key to the server.
pub fn IntegerServerKey::scalar_add(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  scalar : UInt64,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(input.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let width = self.parameters.block_count * 4
  let reduced = if width < 64 {
    scalar & ((1UL << width) - 1UL)
  } else {
    scalar
  }
  let result : Array[@shortint.ShortintCiphertext] = []
  let first_digit = (reduced & 0xFUL).to_uint()
  let (first, initial_carry) = match
    self.inner.scalar_add_with_carry(input.blocks[0], first_digit) {
    Ok(value) => value
    Err(_) => return Err(ShortintFailure)
  }
  result.push(first)
  let mut carry = initial_carry
  for index in 1..<self.parameters.block_count {
    let digit = ((reduced >> (index * 4)) & 0xFUL).to_uint()
    let (partial, digit_carry) = match
      self.inner.scalar_add_with_carry(input.blocks[index], digit) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    let (sum, carry_from_previous) = match
      self.inner.add_with_carry(partial, carry) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    carry = match self.inner.bitor(digit_carry, carry_from_previous) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    result.push(sum)
  }
  Ok({ blocks: result, parameters: self.parameters })
}

///|
fn integer_bitwise(
  server : @shortint.ShortintServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
  parameters : IntegerParameters,
  operation : IntegerBitwiseOp,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(left.parameters, parameters) ||
    !parameters_match(right.parameters, parameters) ||
    left.blocks.length() != parameters.block_count ||
    right.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  let result : Array[@shortint.ShortintCiphertext] = []
  for index in 0..<parameters.block_count {
    let block = match operation {
      And => server.bitand(left.blocks[index], right.blocks[index])
      Or => server.bitor(left.blocks[index], right.blocks[index])
      Xor => server.bitxor(left.blocks[index], right.blocks[index])
    }
    match block {
      Ok(value) => result.push(value)
      Err(_) => return Err(ShortintFailure)
    }
  }
  Ok({ blocks: result, parameters })
}

///|
pub fn IntegerServerKey::bitand(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  integer_bitwise(self.inner, left, right, self.parameters, And)
}

///|
pub fn IntegerServerKey::bitor(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  integer_bitwise(self.inner, left, right, self.parameters, Or)
}

///|
pub fn IntegerServerKey::bitxor(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  integer_bitwise(self.inner, left, right, self.parameters, Xor)
}

///|
pub fn IntegerServerKey::bitnot(
  self : IntegerServerKey,
  input : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(input.parameters, self.parameters) ||
    input.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let blocks : Array[@shortint.ShortintCiphertext] = []
  for block in input.blocks {
    match self.inner.bitnot(block) {
      Ok(value) => blocks.push(value)
      Err(_) => return Err(ShortintFailure)
    }
  }
  Ok({ blocks, parameters: self.parameters })
}

///|
pub fn IntegerServerKey::bit_at(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  index : Int,
) -> Result[BooleanBlock, IntegerError] {
  integer_bit_at(self.inner, input, self.parameters, index)
}

///|
pub fn IntegerServerKey::equal(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[BooleanBlock, IntegerError] {
  if !parameters_match(left.parameters, self.parameters) ||
    !parameters_match(right.parameters, self.parameters) ||
    left.blocks.length() != self.parameters.block_count ||
    right.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match integer_zero_like(self.inner, left, self.parameters) {
    Ok(value) => value.blocks[0]
    Err(error) => return Err(error)
  }
  let mut result = match self.inner.scalar_add(zero, 1U) {
    Ok(value) => value
    Err(_) => return Err(ShortintFailure)
  }
  for index in 0..<self.parameters.block_count {
    let block_equal = match
      self.inner.equal(left.blocks[index], right.blocks[index]) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    result = match self.inner.bitand(result, block_equal) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
  }
  Ok({ inner: result, parameters: self.parameters })
}

///|
fn unsigned_less_than(
  server : @shortint.ShortintServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
  parameters : IntegerParameters,
) -> Result[BooleanBlock, IntegerError] {
  if !parameters_match(left.parameters, parameters) ||
    !parameters_match(right.parameters, parameters) ||
    left.blocks.length() != parameters.block_count ||
    right.blocks.length() != parameters.block_count {
    return Err(KeyMismatch)
  }
  let zero = match integer_zero_like(server, left, parameters) {
    Ok(value) => value.blocks[0]
    Err(error) => return Err(error)
  }
  let mut less = zero
  let mut equal = match server.scalar_add(zero, 1U) {
    Ok(value) => value
    Err(_) => return Err(ShortintFailure)
  }
  let mut index = parameters.block_count - 1
  while index >= 0 {
    let block_less = match
      server.less_than(left.blocks[index], right.blocks[index]) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    let decisive = match server.bitand(equal, block_less) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    less = match server.bitor(less, decisive) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    let block_equal = match
      server.equal(left.blocks[index], right.blocks[index]) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    equal = match server.bitand(equal, block_equal) {
      Ok(value) => value
      Err(_) => return Err(ShortintFailure)
    }
    index = index - 1
  }
  Ok({ inner: less, parameters })
}

///|
pub fn IntegerServerKey::less_than(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[BooleanBlock, IntegerError] {
  let unsigned = match
    unsigned_less_than(self.inner, left, right, self.parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !self.parameters.signed {
    return Ok(unsigned)
  }
  let sign_index = self.parameters.block_count * 4 - 1
  let left_sign = match
    integer_bit_at(self.inner, left, self.parameters, sign_index) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let right_sign = match
    integer_bit_at(self.inner, right, self.parameters, sign_index) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let signs_differ = match
    self.inner.bitxor(left_sign.inner, right_sign.inner) {
    Ok(value) => value
    Err(_) => return Err(ShortintFailure)
  }
  match self.inner.select(signs_differ, left_sign.inner, unsigned.inner) {
    Ok(inner) => Ok({ inner, parameters: self.parameters })
    Err(_) => Err(ShortintFailure)
  }
}

///|
pub fn IntegerServerKey::greater_than(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[BooleanBlock, IntegerError] {
  self.less_than(right, left)
}

///|
pub fn IntegerServerKey::less_or_equal(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[BooleanBlock, IntegerError] {
  let greater = match self.greater_than(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let zero = match integer_zero_like(self.inner, left, self.parameters) {
    Ok(value) => value.blocks[0]
    Err(error) => return Err(error)
  }
  boolean_not(self.inner, greater, zero, self.parameters)
}

///|
pub fn IntegerServerKey::greater_or_equal(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[BooleanBlock, IntegerError] {
  let less = match self.less_than(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let zero = match integer_zero_like(self.inner, left, self.parameters) {
    Ok(value) => value.blocks[0]
    Err(error) => return Err(error)
  }
  boolean_not(self.inner, less, zero, self.parameters)
}

///|
pub fn IntegerServerKey::select(
  self : IntegerServerKey,
  selector : BooleanBlock,
  when_true : IntegerCiphertext,
  when_false : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  if !parameters_match(selector.parameters, self.parameters) ||
    !parameters_match(when_true.parameters, self.parameters) ||
    !parameters_match(when_false.parameters, self.parameters) ||
    when_true.blocks.length() != self.parameters.block_count ||
    when_false.blocks.length() != self.parameters.block_count {
    return Err(KeyMismatch)
  }
  let blocks : Array[@shortint.ShortintCiphertext] = []
  for index in 0..<self.parameters.block_count {
    match
      self.inner.select(
        selector.inner,
        when_true.blocks[index],
        when_false.blocks[index],
      ) {
      Ok(value) => blocks.push(value)
      Err(_) => return Err(ShortintFailure)
    }
  }
  Ok({ blocks, parameters: self.parameters })
}

///|
pub fn IntegerServerKey::min(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  let selector = match self.less_than(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  self.select(selector, left, right)
}

///|
pub fn IntegerServerKey::max(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  let selector = match self.less_than(left, right) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  self.select(selector, right, left)
}

///|
pub fn IntegerServerKey::shift_left(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  amount : Int,
) -> Result[IntegerCiphertext, IntegerError] {
  if amount < 0 {
    return Err(InvalidShift)
  }
  let zero = match integer_zero_like(self.inner, input, self.parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let width = self.parameters.block_count * 4
  if amount >= width {
    return Ok(zero)
  }
  let mut result = input
  for _ in 0..<amount {
    result = match
      shift_left_one_internal(
        self.inner,
        result,
        zero.blocks[0],
        self.parameters,
      ) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn IntegerServerKey::shift_right(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  amount : Int,
) -> Result[IntegerCiphertext, IntegerError] {
  if amount < 0 {
    return Err(InvalidShift)
  }
  let zero = match integer_zero_like(self.inner, input, self.parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let width = self.parameters.block_count * 4
  if amount >= width && !self.parameters.signed {
    return Ok(zero)
  }
  let incoming = if self.parameters.signed {
    match integer_bit_at(self.inner, input, self.parameters, width - 1) {
      Ok(value) => value.inner
      Err(error) => return Err(error)
    }
  } else {
    zero.blocks[0]
  }
  let mut result = input
  let count = if amount > width { width } else { amount }
  for _ in 0..<count {
    result = match
      shift_right_one_internal(self.inner, result, incoming, self.parameters) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn IntegerServerKey::rotate_left(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  amount : Int,
) -> Result[IntegerCiphertext, IntegerError] {
  if amount < 0 {
    return Err(InvalidShift)
  }
  let width = self.parameters.block_count * 4
  let mut result = input
  for _ in 0..<(amount % width) {
    let incoming = match
      integer_bit_at(self.inner, result, self.parameters, width - 1) {
      Ok(value) => value.inner
      Err(error) => return Err(error)
    }
    result = match
      shift_left_one_internal(self.inner, result, incoming, self.parameters) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn IntegerServerKey::rotate_right(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  amount : Int,
) -> Result[IntegerCiphertext, IntegerError] {
  if amount < 0 {
    return Err(InvalidShift)
  }
  let width = self.parameters.block_count * 4
  let mut result = input
  for _ in 0..<(amount % width) {
    let incoming = match
      integer_bit_at(self.inner, result, self.parameters, 0) {
      Ok(value) => value.inner
      Err(error) => return Err(error)
    }
    result = match
      shift_right_one_internal(self.inner, result, incoming, self.parameters) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
/// Schoolbook shift-and-add multiplication modulo the configured bit width.
pub fn IntegerServerKey::mul(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  let zero = match integer_zero_like(self.inner, left, self.parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let mut result = zero
  let mut multiplicand = left
  let width = self.parameters.block_count * 4
  for index in 0..<width {
    let selector = match
      integer_bit_at(self.inner, right, self.parameters, index) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let partial = match self.select(selector, multiplicand, zero) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    result = match self.add(result, partial) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    multiplicand = match
      shift_left_one_internal(
        self.inner,
        multiplicand,
        zero.blocks[0],
        self.parameters,
      ) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn IntegerServerKey::scalar_mul(
  self : IntegerServerKey,
  input : IntegerCiphertext,
  scalar : UInt64,
) -> Result[IntegerCiphertext, IntegerError] {
  let zero = match integer_zero_like(self.inner, input, self.parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let width = self.parameters.block_count * 4
  let reduced = if width < 64 {
    scalar & ((1UL << width) - 1UL)
  } else {
    scalar
  }
  let mut result = zero
  let mut multiplicand = input
  for index in 0..<width {
    if ((reduced >> index) & 1UL) == 1UL {
      result = match self.add(result, multiplicand) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
    }
    multiplicand = match
      shift_left_one_internal(
        self.inner,
        multiplicand,
        zero.blocks[0],
        self.parameters,
      ) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
  }
  Ok(result)
}

///|
pub fn IntegerServerKey::unchecked_add(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  self.add(left, right)
}

///|
pub fn IntegerServerKey::smart_add(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  self.add(left, right)
}

///|
pub fn IntegerServerKey::unchecked_sub(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  self.sub(left, right)
}

///|
pub fn IntegerServerKey::smart_sub(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  self.sub(left, right)
}

///|
pub fn IntegerServerKey::unchecked_mul(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  self.mul(left, right)
}

///|
pub fn IntegerServerKey::smart_mul(
  self : IntegerServerKey,
  left : IntegerCiphertext,
  right : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  self.mul(left, right)
}

///|
fn boolean_not(
  server : @shortint.ShortintServerKey,
  input : BooleanBlock,
  zero : @shortint.ShortintCiphertext,
  parameters : IntegerParameters,
) -> Result[BooleanBlock, IntegerError] {
  match server.equal(input.inner, zero) {
    Ok(inner) => Ok({ inner, parameters })
    Err(_) => Err(ShortintFailure)
  }
}

///|
/// Unsigned restoring division. Division by encrypted zero produces a zero
/// quotient and returns the dividend as the remainder.
pub fn IntegerServerKey::div_rem(
  self : IntegerServerKey,
  dividend : IntegerCiphertext,
  divisor : IntegerCiphertext,
) -> Result[(IntegerCiphertext, IntegerCiphertext), IntegerError] {
  if self.parameters.signed {
    return Err(SignedOperationUnsupported)
  }
  let zero = match integer_zero_like(self.inner, dividend, self.parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let divisor_is_zero = match self.equal(divisor, zero) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let mut quotient = zero
  let mut remainder = zero
  let mut index = self.parameters.block_count * 4 - 1
  while index >= 0 {
    let incoming = match
      integer_bit_at(self.inner, dividend, self.parameters, index) {
      Ok(value) => value.inner
      Err(error) => return Err(error)
    }
    remainder = match
      shift_left_one_internal(self.inner, remainder, incoming, self.parameters) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
    let less = match
      unsigned_less_than(self.inner, remainder, divisor, self.parameters) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let greater_or_equal = match
      boolean_not(self.inner, less, zero.blocks[0], self.parameters) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let difference = match self.sub(remainder, divisor) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    remainder = match self.select(greater_or_equal, difference, remainder) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    quotient = match
      shift_left_one_internal(
        self.inner,
        quotient,
        greater_or_equal.inner,
        self.parameters,
      ) {
      Ok((value, _outgoing)) => value
      Err(error) => return Err(error)
    }
    index = index - 1
  }
  let quotient = match self.select(divisor_is_zero, zero, quotient) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let remainder = match self.select(divisor_is_zero, dividend, remainder) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok((quotient, remainder))
}

///|
pub fn IntegerServerKey::div(
  self : IntegerServerKey,
  dividend : IntegerCiphertext,
  divisor : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  match self.div_rem(dividend, divisor) {
    Ok((quotient, _remainder)) => Ok(quotient)
    Err(error) => Err(error)
  }
}

///|
pub fn IntegerServerKey::remainder(
  self : IntegerServerKey,
  dividend : IntegerCiphertext,
  divisor : IntegerCiphertext,
) -> Result[IntegerCiphertext, IntegerError] {
  match self.div_rem(dividend, divisor) {
    Ok((_quotient, remainder)) => Ok(remainder)
    Err(error) => Err(error)
  }
}
