///|
/// Portable runtimes overwrite reachable storage on destruction. The GC may
/// retain old copies, so this is explicitly best-effort.
struct SecretWords {
  words : Array[UInt]
  mut destroyed : Bool
}

///|
fn secret_words_from_array(words : Array[UInt]) -> SecretWords {
  { words: words.copy(), destroyed: false }
}

///|
fn secret_words_get(words : SecretWords, index : Int) -> UInt {
  if words.destroyed {
    0U
  } else {
    words.words[index]
  }
}

///|
fn secret_words_set(words : SecretWords, index : Int, value : UInt) -> Unit {
  if !words.destroyed {
    words.words[index] = value
  }
}

///|
fn secret_words_destroy(words : SecretWords) -> Unit {
  words.words.fill(0U)
  words.destroyed = true
}
