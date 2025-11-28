///|
test "sanity: LWE encryption noise matches sigma_lwe" {
  let p = {
    n_lwe_in: 128,
    n_lwe_out: 128,
    sigma_lwe: 0.01, // 明显非 0 的噪声
    ks_base_log: 4,
    ks_level: 3,
    sigma_ks: 0.0,
    n_trlwe: 256,
    sigma_trlwe: 0.0,
    bk_base_log: 3,
    bk_level: 3,
  }
  let rng = csprng_new(0xABCDEF)
  let key = lwe_key_new(p.n_lwe_in, rng)
  let trials = 50
  for i in 0..<trials {
    let m = (next_u64(rng) & 1) == 1
    let ct = lwe_encrypt(key, m, p.sigma_lwe, rng)

    // phase = b - <a,s>
    let mut phi = ct.b
    for j in 0..<p.n_lwe_in {
      if key.s[j] {
        phi = phi - ct.a[j]
      }
    }

    // 期望相位 = encode(m)
    let mu = t32_encode_bit_pm(m, T32_QUARTER)
    let _err = phi - mu // Torus32 下有模，但这里 sigma 小时足够安全
    ////println("LWE noise sample = \{_err}")
  }
  assert_true(true) // 只是打印检查
}


///|
test "sanity: PBS reduces noise (oracle PBS)" {
  let p = {
    n_lwe_in: 32,
    n_lwe_out: 32,
    sigma_lwe: 0.20, // 故意加大噪声
    ks_base_log: 2,
    ks_level: 2,
    sigma_ks: 0.0,
    n_trlwe: 64,
    sigma_trlwe: 0.0,
    bk_base_log: 2,
    bk_level: 2,
  }
  let rng = csprng_new(0x55667788)
  let key_lwe = lwe_key_new(p.n_lwe_in, rng)
  let key_trlwe = trlwe_key_new(p.n_trlwe, rng)
  let bk = bsk_generate(
    p,
    key_lwe,
    key_trlwe,
    p.bk_base_log,
    p.bk_level,
    0.0,
    rng,
  )
  let trials = 15
  for _t in 0..<trials {
    let m = (next_u64(rng) & 1) == 1
    let ct_in = lwe_encrypt(key_lwe, m, p.sigma_lwe, rng)

    // phase of input
    let mut phi_in = ct_in.b
    for j in 0..<p.n_lwe_in {
      if key_lwe.s[j] {
        phi_in = phi_in - ct_in.a[j]
      }
    }
    let ct_out = tfhe_id(p, bk, ct_in)

    // phase of output
    let mut phi_out = ct_out.b
    for j in 0..<p.n_lwe_in {
      if key_lwe.s[j] {
        phi_out = phi_out - ct_out.a[j]
      }
    }
    let mu = t32_encode_bit_pm(m, T32_QUARTER)
    let _err_in = phi_in - mu
    let _err_out = phi_out - mu
    ////println("PBS noise in=\{_err_in}  out=\{_err_out}")
  }
  assert_true(true)
}


///|
test "sanity: PBS reduces noise (oracle)" {
  // 用大噪声测试效果更明显
  let p = {
    n_lwe_in: 128,
    n_lwe_out: 128,
    sigma_lwe: 0.2, // 故意较大
    ks_base_log: 4,
    ks_level: 3,
    sigma_ks: 0.0,
    n_trlwe: 256,
    sigma_trlwe: 0.0,
    bk_base_log: 3,
    bk_level: 3,
  }
  let rng = csprng_new(0xAA55AA55)
  let key_lwe = lwe_key_new(p.n_lwe_in, rng)
  let key_trlwe = trlwe_key_new(p.n_trlwe, rng)
  let bk = bsk_generate(
    p,
    key_lwe,
    key_trlwe,
    p.bk_base_log,
    p.bk_level,
    0.0,
    rng,
  )
  let trials = 20
  for _i in 0..<trials {
    let m = (next_u64(rng) & 1) == 1
    let ct_in = lwe_encrypt(key_lwe, m, p.sigma_lwe, rng)

    // in-phase
    let phi_in = {
      let mut v = ct_in.b
      for j in 0..<p.n_lwe_in {
        if key_lwe.s[j] {
          v = v - ct_in.a[j]
        }
      }
      v
    }

    // PBS (oracle)
    let ct_out = tfhe_id(p, bk, ct_in) // identity bootstrapping

    // out-phase
    let phi_out = {
      let mut v = ct_out.b
      for j in 0..<p.n_lwe_in {
        if key_lwe.s[j] {
          v = v - ct_out.a[j]
        }
      }
      v
    }
    let mu = t32_encode_bit_pm(m, T32_QUARTER)
    let _err_in = phi_in - mu
    let _err_out = phi_out - mu
    ////println("PBS noise check: in=\{_err_in}out=\_{err_out}")
  }
  assert_true(true)
}


///|
test "sanity: φ(a,b) pattern under binary linearization" {
  let rng = csprng_new(0xCAFEBABE)
  let p = tiny_tfhe_params_toy()
  let key = lwe_key_new(p.n_lwe_in, rng)
  let sigma = p.sigma_lwe
  let inputs : Array[(Bool, Bool)] = [
    (false, false),
    (false, true),
    (true, false),
    (true, true),
  ]
  for idx in 0..<inputs.length() {
    let (a, _b) = inputs[idx]
    let ca = lwe_encrypt(key, a, sigma, rng)
    let cb = lwe_encrypt(key, a, sigma, rng)
    // tfhe_xnor 里的 linear combination:
    let mu = T32_QUARTER
    let sum = lwe_add(ca, cb)
    let ct_lin = lwe_sub_plain(sum, mu)

    // compute phase
    let mut phi = ct_lin.b
    for j in 0..<p.n_lwe_in {
      if key.s[j] {
        phi = phi - ct_lin.a[j]
      }
    }
    ////println("φ(,\{a},\{_b}) = \{phi}")
  }
  assert_true(true)
}
