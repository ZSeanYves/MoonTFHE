///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend RandomError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RandomError with Eq::{not_equal, equal}

///|
pub extend RandomDomain with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend RandomDomain with Eq::{not_equal, equal}
