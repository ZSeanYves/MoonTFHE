///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend PolynomialError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PolynomialError with Eq::{not_equal, equal}
