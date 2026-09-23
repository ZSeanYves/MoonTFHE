///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend IntegerError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend IntegerError with Eq::{not_equal, equal}
