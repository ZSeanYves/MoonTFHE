// 占位版 NTT 接口：v0.2 做性能优化时再填充真实实现。

/// 计划对象占位（将来可换成包含根表、bit-reverse 索引等的结构体）

/// 预生成 NTT 计划（占位：直接返回 Unit）
pub fn ntt_plan_new(_n : Int) -> Unit {
  ()
}

/// 原地 NTT 变换（占位：不对输入做任何修改）
pub fn ntt_inplace(_plan : Unit, _a : Array[Int]) -> Unit {
  // TODO: implement NTT in v0.2
}

/// 原地逆 NTT 变换（占位：不对输入做任何修改）
pub fn intt_inplace(_plan : Unit, _a : Array[Int]) -> Unit {
  // TODO: implement inverse NTT in v0.2
}
