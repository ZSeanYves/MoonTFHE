///|
declare pub type ParameterSet

///|
declare pub fn boolean_110_reference() -> ParameterSet

///|
declare pub fn boolean_128_reference() -> ParameterSet

///|
declare pub fn boolean_test_record() -> ParameterSet

///|
declare pub fn ParameterSet::validate(
  self : ParameterSet,
) -> Result[Unit, ParameterValidationError]
