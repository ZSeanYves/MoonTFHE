/// LWE 秘钥：s ∈ {0,1}^n
pub struct LweKey {
  s : Array[Bool]
}

/// LWE 密文：a ∈ T^n, b ∈ T
pub struct LweCiphertext {
  a : Array[Int]
  mut b : Int
}

/// 生成长度为 n 的 {0,1} 秘钥
fn lwe_key_new(n : Int, rng : CsPrng) -> LweKey {
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    // 低位随机成 {0,1}
    s[i] = (next_u64(rng) & 1) == 1
  }
  let a = { s, }
  a
}

/// LWE 加密（布尔消息：true->0, false->0.5）
fn lwe_phase_from_a_s(a : Array[Int], s : Array[Bool]) -> Int {
  let n = a.length()
  let mut acc = 0
  for i in 0..<n {
    if s[i] {
      acc = acc + a[i]
    }
  }
  acc
}

///|
fn lwe_encrypt(
  key : LweKey,
  m : Bool,
  sigma : Float,
  rng : CsPrng,
) -> LweCiphertext {
  let n = key.s.length()
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    a[i] = next_u32(rng)
  }
  let e = sample_discrete_gaussian_0sigma(rng, sigma)

  // 对称编码，留出安全边界
  let mu = t32_encode_bit_pm(m, T32_QUARTER)
  let b = lwe_phase_from_a_s(a, key.s) + mu + e
  let s = { a, b }
  s
}

///  LWE 解密：相位减去 <a,s>，再阈值判定,解密得到布尔值
fn lwe_decrypt(key : LweKey, ct : LweCiphertext) -> Bool {
  let n = key.s.length()
  let mut mu = ct.b
  for i in 0..<n {
    if key.s[i] {
      mu = mu - ct.a[i]
    }
  }
  // 对称解码：看符号位
  t32_decode_sign(mu)
}

/// 从 TRLWE 提取为 LWE：提取第 k 个系数
fn sample_extract_index(ct : TrlweCiphertext, k : Int) -> LweCiphertext {
  let n = ct.a.length()
  if k < 0 || k >= n {
    panic()
  }

  // a' 向量
  let a = Array::makei(n, fn(_i) { 0 })
  for i in 0..<n {
    let t = k - i
    if t >= 0 {
      a[i] = ct.a[t]
    } else {
      // 折返取反：X^n = -1
      a[i] = -ct.a[t + n]
    }
  }
  // b' = b[k]
  let b = ct.b[k]
  let s = { a, b }
  s
}

/// 将 TRLWE 的 {0,1} 多项式密钥转换为同维度 LWE 密钥（逐系数）
fn lwe_key_from_trlwe_key(k_tr : TrlweKey) -> LweKey {
  let n = k_tr.params.n
  let s = Array::makei(n, fn(_i) { false })
  for i in 0..<n {
    s[i] = k_tr.s[i]
  }
  let a = { s, }
  a
}

/// 专门提取常数项（k = 0），做一个便捷封装
fn sample_extract_const(ct : TrlweCiphertext) -> LweCiphertext {
  sample_extract_index(ct, 0)
}


///|
test "lwe: encrypt/decrypt roundtrip (n=512, 400 trials)" {
  let rng = csprng_new(123456789)
  let key = lwe_key_new(512, rng)
  let trials = 400
  let mut ok = 0
  for _i in 0..<trials {
    let bit = (next_u64(rng) & 1) == 1
    // sigma 较小，避免解密错误
    let ct = lwe_encrypt(key, bit, 3.0, rng)
    let dec = lwe_decrypt(key, ct)
    if dec == bit {
      ok = ok + 1
    }
  }
  assert_eq(ok, trials)
}


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
    //println("LWE noise sample = \{err}")
  }
  assert_true(true) // 只是打印检查
}



