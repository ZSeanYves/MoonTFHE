///|
/// Explicit trait extensions required by the latest MoonBit compiler.
pub extend KeyGenerationError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend KeyGenerationError with Eq::{not_equal, equal}

///|
pub extend DecryptionError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend DecryptionError with Eq::{not_equal, equal}

///|
pub extend EvaluationError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend EvaluationError with Eq::{not_equal, equal}

///|
pub extend LutError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend LutError with Eq::{not_equal, equal}

///|
pub extend SerializationError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SerializationError with Eq::{not_equal, equal}

///|
pub extend Backend with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend Backend with Eq::{not_equal, equal}

///|
pub extend SerializationKeyError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend SerializationKeyError with Eq::{not_equal, equal}

///|
pub extend BackendError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend BackendError with Eq::{not_equal, equal}
