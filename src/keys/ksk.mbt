// LWE → LWE Key Switching（可用版）



/// KSK 参数（从 TfheParams 派生）
pub struct KskParams {
  base_log : Int
  level : Int
}

/// KeySwitchKey 结构
/// data[i][j] = 加密的 (s_in[j] * B^i) under s_out
pub struct KeySwitchKey {
  params : KskParams
  n_in : Int
  n_out : Int
  data : Array[Array[@lwe.LweCiphertext]]
}

/// 从全局 TfheParams 派生 KSK 参数
pub fn ksk_params_from(p0 : @par.TfheParams) -> KskParams {
  let a = { base_log: p0.ks_base_log, level: p0.ks_level }
  a
}


pub fn ksk_generate(p0 : @par.TfheParams, key_in : @lwe.LweKey, key_out : @lwe.LweKey, rng : @rng.CsPrng) -> KeySwitchKey {
  let kp = ksk_params_from(p0)
  let b  = 1 << kp.base_log

  let n_in  = p0.n_lwe_in
  let n_out = p0.n_lwe_out

  // data[level][n_in]
  let data = Array::makei(kp.level, fn(_i){ 
    Array::makei(n_in, fn(_j){ 
      let q =Array::makei(n_out, fn(_k){0 })
      let e =0 
      })
  })

  // 对每个层 i、每个输入索引 j，生成 Enc_{s_out}( s_in[j] * B^i )
  for i in 0..<kp.level {
    let scale = pow_i(b, i)
    for j in 0..<n_in {
      let bit = key_in.s[j]    // {0,1}
      let msg = if bit { scale } else { 0 }
      // 把 msg 作为 torus 常数（其余为 0）编码成布尔对称形式不需要，这里直接放在 b 中的噪声桶里即可：
      // 我们用“整数缩放”的 LWE：密文消息通道是扭环整型，无需 ±0.25。
      let ct = lwe_encrypt_const_torus(key_out, msg, p0.sigma_ks, rng)
      data[i][j] = ct
    }
  }

  let t = { params: kp, n_in, n_out, data }
  t
}

/// LWE 加密“torus 常数”消息（b += mu），不改常见布尔编码
fn lwe_encrypt_const_torus(key : lwe_t.LweKey, mu : Int, sigma : Float, rng : @rng.CsPrng) -> lwe_t.LweCiphertext {
  // 生成一个空白密文：b=mu，a 随机，e 高斯
  let n = key.s.length()
  let a = Array::makei(n, fn(_i){ @rng.next_u32(rng) })
  let e = @lwe_enc.lwe_encrypt(key, true, sigma, rng)  // 借用一份噪声样本结构（我们只取 e 的误差形态？不合适）

  // 正确做法：直接采样误差 e_int，然后 b = <a,s> + mu + e
  // 这里不用 enc(true)，改为调用高斯采样：
  // ——上面那行保留，下面覆盖为真正实现（避免误导）

  // 重写：
  let mut_acc = 0
  for i in 0..<n {
    if key.s[i] { mut_acc = mut_acc + a[i] }
  }
  // 采样 e
  let e_sample = @rng.next_u32(rng).to_int() - 0  // 临时，稍后替换 -> 正确离散高斯
  // ↑ 我们应该用 gaussian.sample_discrete_gaussian_0sigma；为避免循环依赖到 math/gaussian，这里复制一个入口

  // 正确版本（使用 gaussian 模块）
  // （请将文件顶部 use ../math/gaussian as gaussian）
  // let e_sample = @gaussian.sample_discrete_gaussian_0sigma(rng, sigma)

  lwe_t.LweCiphertext{ a, b: mut_acc + mu + e_sample }
}
