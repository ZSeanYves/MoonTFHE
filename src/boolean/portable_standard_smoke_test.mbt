///|
fn install_portable_smoke_entropy() -> Unit {
  let counter = @ref.new(0U)
  @random.install_entropy_provider(fn(count) {
    if count < 0 {
      None
    } else {
      let bytes = Array::makei(count, fn(index) {
        let word = counter.val + index.reinterpret_as_uint() * 0x9E3779B9U
        (word ^ (word >> 11) ^ (word >> 23)).to_byte()
      })
      counter.val = counter.val + count.reinterpret_as_uint() + 1U
      Some(Bytes::from_array(bytes))
    }
  })
}

///|
#skip("scheduled portable standard reference smoke")
test "portable 110: host entropy reference keygen and NAND" {
  install_portable_smoke_entropy()
  let parameters = boolean_110_parameters()
  let (client, server) = generate_keys(parameters).unwrap()
  let result = server.nand(client.encrypt(true), client.encrypt(false)).unwrap()
  assert_eq(client.decrypt(result), Ok(true))
  @random.clear_entropy_provider()
}
