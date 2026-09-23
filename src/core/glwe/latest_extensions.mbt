///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend GlweParameters with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend GlweParameters with Eq::{not_equal, equal}

///|
pub extend GlweError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend GlweError with Eq::{not_equal, equal}
