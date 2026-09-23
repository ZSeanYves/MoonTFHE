///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend GgswParameters with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend GgswParameters with Eq::{not_equal, equal}

///|
pub extend GgswError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend GgswError with Eq::{not_equal, equal}
