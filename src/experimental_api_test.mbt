///|
test "experimental facade: keygen encrypt not decrypt" {
  let client = experimental_keygen(64, 3.0, 0x4D4F4F4E)
  for message in [false, true] {
    let ciphertext = client.encrypt(message)
    assert_eq(client.decrypt(ciphertext.not()), !message)
  }
}
