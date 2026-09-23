///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend ShortintError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend ShortintError with Eq::{not_equal, equal}
