///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend DecompositionError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DecompositionError with Eq::{not_equal, equal}

///|
pub extend KeySwitchError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend KeySwitchError with Eq::{not_equal, equal}
