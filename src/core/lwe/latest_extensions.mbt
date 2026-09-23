///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend LweCiphertext with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend LweCiphertext with Eq::{not_equal, equal}

///|
pub extend LweError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend LweError with Eq::{not_equal, equal}
