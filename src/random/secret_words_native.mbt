///|
/// Native secret state is held by a finalizer-backed external object.
type SecretWords

///|
#borrow(words)
extern "c" fn secret_words_new_ffi(words : FixedArray[UInt]) -> SecretWords = "moonbit_tfhe_secret_words_new"

///|
#borrow(words)
extern "c" fn secret_words_get_ffi(words : SecretWords, index : Int) -> UInt = "moonbit_tfhe_secret_words_get"

///|
#borrow(words)
extern "c" fn secret_words_set_ffi(
  words : SecretWords,
  index : Int,
  value : UInt,
) -> Unit = "moonbit_tfhe_secret_words_set"

///|
#borrow(words)
extern "c" fn secret_words_destroy_ffi(words : SecretWords) -> Unit = "moonbit_tfhe_secret_words_destroy"

///|
fn secret_words_from_array(words : Array[UInt]) -> SecretWords {
  secret_words_new_ffi(FixedArray::from_array(words))
}

///|
fn secret_words_get(words : SecretWords, index : Int) -> UInt {
  secret_words_get_ffi(words, index)
}

///|
fn secret_words_set(words : SecretWords, index : Int, value : UInt) -> Unit {
  secret_words_set_ffi(words, index, value)
}

///|
fn secret_words_destroy(words : SecretWords) -> Unit {
  secret_words_destroy_ffi(words)
}
