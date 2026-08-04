///|
pub suberror IntegerError {
  InvalidBlockCount
  InvalidValue
  KeyMismatch
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
