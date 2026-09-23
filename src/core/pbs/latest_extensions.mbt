///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend PbsOrder with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PbsOrder with Eq::{not_equal, equal}

///|
pub extend BooleanLut with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend BooleanLut with Eq::{not_equal, equal}

///|
pub extend PbsError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PbsError with Eq::{not_equal, equal}

///|
pub extend PackedShapeError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend PackedShapeError with Eq::{not_equal, equal}
