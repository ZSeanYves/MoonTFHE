///|
pub enum PbsOrder {
  KeyswitchBootstrap
  BootstrapKeyswitch
} derive(Debug, Eq)

///|
pub fn bootstrap_keyswitch_order() -> PbsOrder {
  BootstrapKeyswitch
}

///|
pub fn keyswitch_bootstrap_order() -> PbsOrder {
  KeyswitchBootstrap
}

///|
/// A fixed two-point Boolean programmable LUT. The full arbitrary torus LUT
/// representation is added with the Fourier BSK backend in C4.
pub struct BooleanLut {
  false_value : @torus.Torus32
  true_value : @torus.Torus32
} derive(Debug, Eq)

///|
#warnings("-unused_constructor")
pub suberror PbsError {
  InvalidLut
  InvalidPolynomialSize
  InputDimensionMismatch
  BootstrapKeyShapeMismatch
  BlindRotationFailure
  SampleExtractionFailure
  KeyswitchFailure
  UnsupportedOrder
  InvalidTableLength
} derive(Debug, Eq)

///|
/// Secret-free bootstrapping material. Construction accepts only encrypted
/// GGSW controls and an encrypted key-switching key.
pub struct BootstrapKey {
  input_dimension : @params.LweDimension
  glwe_parameters : @glwe.GlweParameters
  ggsw_parameters : @ggsw.GgswParameters
  coefficient_bsk : FixedArray[UInt]?
  key_switch : @keyswitch.KeySwitchKey?
  key_switch_input : @params.LweDimension
  key_switch_output : @params.LweDimension
  key_switch_decomposition_parameters : @params.DecompositionParameters
  order : PbsOrder
  fourier : @provider.FourierBootstrapKey?
  native_context : @provider.PbsContext?
  workspace : @ref.Ref[PbsWorkspace]
}

///|
pub struct PbsWorkspace {
  state_a : FixedArray[UInt]
  state_b : FixedArray[UInt]
  rotated : FixedArray[UInt]
  difference : FixedArray[UInt]
  digits : FixedArray[UInt]
  decomposition_digits : FixedArray[Int]
  extracted : FixedArray[UInt]
  ksk_result : FixedArray[UInt]
  ksk_digits : FixedArray[Int]
}

///|
fn pbs_workspace_new(
  glwe_parameters : @glwe.GlweParameters,
  ggsw_parameters : @ggsw.GgswParameters,
  ksk_output_dimension : @params.LweDimension,
  ksk_level : Int,
) -> PbsWorkspace {
  let n = glwe_parameters.polynomial_size()
  let glwe_size = (glwe_parameters.glwe_dimension() + 1) * n
  {
    state_a: FixedArray::make(glwe_size, 0U),
    state_b: FixedArray::make(glwe_size, 0U),
    rotated: FixedArray::make(glwe_size, 0U),
    difference: FixedArray::make(glwe_size, 0U),
    digits: FixedArray::make(ggsw_parameters.level() * glwe_size, 0U),
    decomposition_digits: FixedArray::make(ggsw_parameters.level(), 0),
    extracted: FixedArray::make(glwe_parameters.glwe_dimension() * n + 1, 0U),
    ksk_result: FixedArray::make(ksk_output_dimension.value() + 1, 0U),
    ksk_digits: FixedArray::make(ksk_level, 0),
  }
}

///|
pub fn boolean_lut(
  false_value : @torus.Torus32,
  true_value : @torus.Torus32,
) -> BooleanLut {
  { false_value, true_value }
}

///|
pub fn BooleanLut::evaluate_reference(
  self : BooleanLut,
  input : Bool,
) -> @torus.Torus32 {
  if input {
    self.true_value
  } else {
    self.false_value
  }
}

///|
pub fn BooleanLut::false_value(self : BooleanLut) -> @torus.Torus32 {
  self.false_value
}

///|
pub fn BooleanLut::true_value(self : BooleanLut) -> @torus.Torus32 {
  self.true_value
}

///|
pub fn bootstrap_key_from_encrypted_parts(
  input_dimension : @params.LweDimension,
  glwe_parameters : @glwe.GlweParameters,
  controls : Array[@ggsw.GgswCiphertext],
  key_switch : @keyswitch.KeySwitchKey,
  order : PbsOrder,
) -> Result[BootstrapKey, PbsError] {
  if controls.length() != input_dimension.value() {
    return Err(BootstrapKeyShapeMismatch)
  }
  if controls.length() == 0 {
    return Err(BootstrapKeyShapeMismatch)
  }
  let ggsw_parameters = controls[0].parameters()
  let flat_size = ggsw_parameters.flat_size()
  let coefficient_bsk = FixedArray::make(controls.length() * flat_size, 0U)
  for index in 0..<controls.length() {
    if controls[index].parameters() != ggsw_parameters ||
      controls[index].validate() is Err(_) {
      return Err(BootstrapKeyShapeMismatch)
    }
    let flat = controls[index].flat_u32_copy()
    for offset in 0..<flat_size {
      coefficient_bsk[index * flat_size + offset] = flat[offset]
    }
  }
  bootstrap_key_from_flat_encrypted_parts(
    input_dimension,
    glwe_parameters,
    ggsw_parameters,
    coefficient_bsk,
    key_switch,
    order,
    None,
  )
}

///|
/// Construct a BSK from its canonical contiguous coefficient representation.
pub fn bootstrap_key_from_flat_encrypted_parts(
  input_dimension : @params.LweDimension,
  glwe_parameters : @glwe.GlweParameters,
  ggsw_parameters : @ggsw.GgswParameters,
  coefficient_bsk : FixedArray[UInt],
  key_switch : @keyswitch.KeySwitchKey,
  order : PbsOrder,
  fourier : @provider.FourierBootstrapKey?,
) -> Result[BootstrapKey, PbsError] {
  if ggsw_parameters.glwe() != glwe_parameters ||
    coefficient_bsk.length() !=
    input_dimension.value() * ggsw_parameters.flat_size() {
    return Err(BootstrapKeyShapeMismatch)
  }
  let extracted_dimension = match
    @params.lwe_dimension(
      glwe_parameters.glwe_dimension() * glwe_parameters.polynomial_size(),
    ) {
    Ok(value) => value
    Err(_) => return Err(BootstrapKeyShapeMismatch)
  }
  if key_switch.input_dimension() != extracted_dimension ||
    key_switch.output_dimension() != input_dimension {
    return Err(BootstrapKeyShapeMismatch)
  }
  Ok({
    input_dimension,
    glwe_parameters,
    ggsw_parameters,
    coefficient_bsk: Some(coefficient_bsk),
    key_switch: Some(key_switch),
    key_switch_input: extracted_dimension,
    key_switch_output: input_dimension,
    key_switch_decomposition_parameters: key_switch.decomposition(),
    order,
    fourier,
    native_context: None,
    workspace: Ref(
      pbs_workspace_new(
        glwe_parameters,
        ggsw_parameters,
        key_switch.output_dimension(),
        key_switch.decomposition().level(),
      ),
    ),
  })
}

///|
/// Construct the native production representation. Coefficient BSK and KSK
/// buffers are consumed during context creation and are not retained by the
/// MoonBit evaluation key.
pub fn bootstrap_key_from_flat_native_parts(
  input_dimension : @params.LweDimension,
  glwe_parameters : @glwe.GlweParameters,
  ggsw_parameters : @ggsw.GgswParameters,
  coefficient_bsk : FixedArray[UInt],
  key_switch_input : @params.LweDimension,
  key_switch_output : @params.LweDimension,
  key_switch_decomposition_parameters : @params.DecompositionParameters,
  key_switch_data : FixedArray[UInt],
  order : PbsOrder,
) -> Result[BootstrapKey, PbsError] {
  if ggsw_parameters.glwe() != glwe_parameters ||
    coefficient_bsk.length() !=
    input_dimension.value() * ggsw_parameters.flat_size() ||
    key_switch_input.value() !=
    glwe_parameters.glwe_dimension() * glwe_parameters.polynomial_size() ||
    key_switch_output != input_dimension {
    return Err(BootstrapKeyShapeMismatch)
  }
  let expected_ksk = key_switch_input.value() *
    key_switch_decomposition_parameters.level() *
    (key_switch_output.value() + 1)
  if key_switch_data.length() != expected_ksk {
    return Err(BootstrapKeyShapeMismatch)
  }
  let native_context = match
    @provider.pbs_context_new(
      glwe_parameters.polynomial_size(),
      input_dimension.value(),
      glwe_parameters.glwe_dimension(),
      ggsw_parameters.base_log(),
      ggsw_parameters.level(),
      key_switch_input.value(),
      key_switch_output.value(),
      key_switch_decomposition_parameters.base_log(),
      key_switch_decomposition_parameters.level(),
      match order {
        KeyswitchBootstrap => 0
        BootstrapKeyswitch => 1
      },
      coefficient_bsk,
      key_switch_data,
    ) {
    Ok(value) => value
    Err(_) => return Err(BootstrapKeyShapeMismatch)
  }
  Ok({
    input_dimension,
    glwe_parameters,
    ggsw_parameters,
    coefficient_bsk: None,
    key_switch: None,
    key_switch_input,
    key_switch_output,
    key_switch_decomposition_parameters,
    order,
    fourier: None,
    native_context: Some(native_context),
    workspace: Ref(
      pbs_workspace_new(
        glwe_parameters,
        ggsw_parameters,
        key_switch_output,
        key_switch_decomposition_parameters.level(),
      ),
    ),
  })
}

///|
/// Adopt a fully initialized native context. This constructor lets native
/// key generation stream one coefficient GGSW at a time into Fourier storage
/// instead of retaining a complete coefficient BSK during conversion.
pub fn bootstrap_key_from_native_context(
  input_dimension : @params.LweDimension,
  glwe_parameters : @glwe.GlweParameters,
  ggsw_parameters : @ggsw.GgswParameters,
  key_switch_input : @params.LweDimension,
  key_switch_output : @params.LweDimension,
  key_switch_decomposition_parameters : @params.DecompositionParameters,
  order : PbsOrder,
  native_context : @provider.PbsContext,
) -> Result[BootstrapKey, PbsError] {
  if ggsw_parameters.glwe() != glwe_parameters ||
    key_switch_input.value() !=
    glwe_parameters.glwe_dimension() * glwe_parameters.polynomial_size() ||
    key_switch_output != input_dimension ||
    !native_context.is_ready() {
    return Err(BootstrapKeyShapeMismatch)
  }
  Ok({
    input_dimension,
    glwe_parameters,
    ggsw_parameters,
    coefficient_bsk: None,
    key_switch: None,
    key_switch_input,
    key_switch_output,
    key_switch_decomposition_parameters,
    order,
    fourier: None,
    native_context: Some(native_context),
    workspace: Ref(
      pbs_workspace_new(
        glwe_parameters,
        ggsw_parameters,
        key_switch_output,
        key_switch_decomposition_parameters.level(),
      ),
    ),
  })
}

///|
pub fn BootstrapKey::input_dimension(
  self : BootstrapKey,
) -> @params.LweDimension {
  self.input_dimension
}

///|
pub fn BootstrapKey::glwe_parameters(
  self : BootstrapKey,
) -> @glwe.GlweParameters {
  self.glwe_parameters
}

///|
pub fn BootstrapKey::ggsw_parameters(
  self : BootstrapKey,
) -> @ggsw.GgswParameters {
  self.ggsw_parameters
}

///|
pub fn BootstrapKey::control_count(self : BootstrapKey) -> Int {
  self.input_dimension.value()
}

///|
pub fn BootstrapKey::coefficient_bsk_copy(
  self : BootstrapKey,
) -> Result[FixedArray[UInt], PbsError] {
  match self.coefficient_bsk {
    Some(value) => Ok(value.copy())
    None =>
      match self.native_context {
        Some(context) =>
          match context.export_coefficients() {
            Ok(value) => Ok(value)
            Err(_) => Err(BootstrapKeyShapeMismatch)
          }
        None => Err(BootstrapKeyShapeMismatch)
      }
  }
}

///|
pub fn BootstrapKey::key_switch_input_dimension(
  self : BootstrapKey,
) -> @params.LweDimension {
  self.key_switch_input
}

///|
pub fn BootstrapKey::key_switch_output_dimension(
  self : BootstrapKey,
) -> @params.LweDimension {
  self.key_switch_output
}

///|
pub fn BootstrapKey::key_switch_decomposition(
  self : BootstrapKey,
) -> @params.DecompositionParameters {
  self.key_switch_decomposition_parameters
}

///|
pub fn BootstrapKey::key_switch_flat_copy(
  self : BootstrapKey,
) -> Result[FixedArray[UInt], PbsError] {
  match self.key_switch {
    Some(value) => Ok(value.flat_u32_copy())
    None =>
      match self.native_context {
        Some(context) =>
          match context.export_ksk() {
            Ok(value) => Ok(value)
            Err(_) => Err(BootstrapKeyShapeMismatch)
          }
        None => Err(BootstrapKeyShapeMismatch)
      }
  }
}

///|
pub fn BootstrapKey::native_resident_bytes(self : BootstrapKey) -> Int64 {
  match self.native_context {
    Some(context) => context.resident_bytes()
    None => 0L
  }
}

///|
pub fn BootstrapKey::native_stage_metrics(
  self : BootstrapKey,
) -> @provider.PbsStageMetrics? {
  match self.native_context {
    Some(context) => Some(context.stage_metrics())
    None => None
  }
}

///|
pub fn BootstrapKey::native_memory_metrics(
  self : BootstrapKey,
) -> @provider.PbsMemoryMetrics? {
  match self.native_context {
    Some(context) => Some(context.memory_metrics())
    None => None
  }
}

///|
/// Measure Rust provider allocations while evaluating a standard PBS into a
/// caller-owned output buffer. Input flattening and result construction happen
/// outside the measurement window and are intentionally reported separately
/// from the native kernel.
pub fn BootstrapKey::native_kernel_allocation_count(
  self : BootstrapKey,
  input : @lwe.LweCiphertext,
  lut : BooleanLut,
  iterations : Int,
) -> Result[Int64, PbsError] {
  let context = match self.native_context {
    Some(value) => value
    None => return Err(BlindRotationFailure)
  }
  let expected_input = match self.order {
    BootstrapKeyswitch => self.input_dimension
    KeyswitchBootstrap => self.key_switch_input
  }
  let output_dimension = match self.order {
    BootstrapKeyswitch => self.key_switch_output
    KeyswitchBootstrap => self.key_switch_input
  }
  if iterations <= 0 || input.parameters() != expected_input {
    return Err(InputDimensionMismatch)
  }
  let accumulator = match lut.accumulator(self.glwe_parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let output = FixedArray::make(output_dimension.value() + 1, 0U)
  match
    context.measure_kernel_allocations(
      input.flat_u32_copy(),
      accumulator.flat_u32_copy(),
      output,
      iterations,
    ) {
    Ok(value) => Ok(value)
    Err(_) => Err(BlindRotationFailure)
  }
}

///|
pub fn BootstrapKey::order(self : BootstrapKey) -> PbsOrder {
  self.order
}

///|
fn BootstrapKey::control(
  self : BootstrapKey,
  index : Int,
) -> Result[@ggsw.GgswCiphertext, PbsError] {
  if index < 0 || index >= self.input_dimension.value() {
    return Err(BootstrapKeyShapeMismatch)
  }
  let flat_size = self.ggsw_parameters.flat_size()
  let offset = index * flat_size
  let coefficient_bsk = match self.coefficient_bsk {
    Some(value) => value
    None => return Err(BootstrapKeyShapeMismatch)
  }
  match
    @ggsw.ggsw_from_flat_u32(
      self.ggsw_parameters,
      FixedArray::makei(flat_size, fn(word) { coefficient_bsk[offset + word] }),
    ) {
    Ok(value) => Ok(value)
    Err(_) => Err(BootstrapKeyShapeMismatch)
  }
}

///|
fn BootstrapKey::fourier_external_product_add_into(
  self : BootstrapKey,
  key : @provider.FourierBootstrapKey,
  control_index : Int,
  input : @glwe.GlweCiphertext,
  addend : FixedArray[UInt],
  output : FixedArray[UInt],
) -> Result[Unit, PbsError] {
  if input.parameters() != self.glwe_parameters {
    return Err(InputDimensionMismatch)
  }
  let n = self.glwe_parameters.polynomial_size()
  let columns = self.glwe_parameters.glwe_dimension() + 1
  let level = self.ggsw_parameters.level()
  let decomposition = match
    @params.decomposition_parameters(self.ggsw_parameters.base_log(), level) {
    Ok(value) => value
    Err(_) => return Err(BlindRotationFailure)
  }
  let workspace = self.workspace.val
  let digits = workspace.digits
  let decomposition_digits = workspace.decomposition_digits
  for component in 0..<columns {
    for coefficient in 0..<n {
      let word = match input.word_at(component * n + coefficient) {
        Ok(value) => value
        Err(_) => return Err(BlindRotationFailure)
      }
      match
        @keyswitch.signed_gadget_decompose_into(
          @torus.Torus32::from_uint(word),
          decomposition,
          decomposition_digits,
        ) {
        Ok(_) => ()
        Err(_) => return Err(BlindRotationFailure)
      }
      for level_index in 0..<level {
        let row = level_index * columns + component
        digits[row * n + coefficient] = decomposition_digits[level_index].reinterpret_as_uint()
      }
    }
  }
  match key.blind_rotation_step(control_index, digits, addend, output) {
    Ok(_) => Ok(())
    Err(_) => Err(BlindRotationFailure)
  }
}

///|
fn polynomial_log_modulus(size : Int) -> Result[Int, PbsError] {
  if size <= 0 || (size & (size - 1)) != 0 || size > 32768 {
    return Err(InvalidPolynomialSize)
  }
  let mut value = size
  let mut log = 0
  while value > 1 {
    value = value >> 1
    log = log + 1
  }
  Ok(log)
}

///|
fn BooleanLut::accumulator(
  self : BooleanLut,
  parameters : @glwe.GlweParameters,
) -> Result[@glwe.GlweCiphertext, PbsError] {
  let n = parameters.polynomial_size()
  if polynomial_log_modulus(n) is Err(_) ||
    self.false_value != self.true_value.neg() {
    return Err(InvalidLut)
  }
  // With the blind-rotation sign convention, a positive input extracts the
  // negated half while a negative input extracts this stored half. Filling the
  // whole half also absorbs modulus-switch rounding around +/-1/8.
  let polynomial = Array::make(n, self.false_value)
  match @glwe.glwe_trivial(parameters, polynomial) {
    Ok(value) => Ok(value)
    Err(_) => Err(InvalidLut)
  }
}

///|
pub fn BootstrapKey::blind_rotate(
  self : BootstrapKey,
  accumulator : @glwe.GlweCiphertext,
  input : @lwe.LweCiphertext,
) -> Result[@glwe.GlweCiphertext, PbsError] {
  if input.parameters() != self.input_dimension ||
    accumulator.parameters() != self.glwe_parameters {
    return Err(InputDimensionMismatch)
  }
  let n = self.glwe_parameters.polynomial_size()
  let log_n = match polynomial_log_modulus(n) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let modulus = match @torus.CiphertextModulus::power_of_two(log_n + 1) {
    Ok(value) => value
    Err(_) => return Err(InvalidPolynomialSize)
  }
  let initial_rotation = match input.b().modulus_switch(modulus) {
    Ok(value) => value
    Err(_) => return Err(BlindRotationFailure)
  }
  let workspace = self.workspace.val
  match
    accumulator.rotate_negacyclic_into(initial_rotation, workspace.state_a) {
    Ok(_) => ()
    Err(_) => return Err(BlindRotationFailure)
  }
  let mut active_a = true
  for index in 0..<self.input_dimension.value() {
    let switched = match input.mask_at(index) {
      Ok(value) =>
        match value.modulus_switch(modulus) {
          Ok(value) => value
          Err(_) => return Err(BlindRotationFailure)
        }
      Err(_) => return Err(BlindRotationFailure)
    }
    if switched != 0 {
      let current_buffer = if active_a {
        workspace.state_a
      } else {
        workspace.state_b
      }
      let next_buffer = if active_a {
        workspace.state_b
      } else {
        workspace.state_a
      }
      let current = match
        @glwe.glwe_ciphertext_from_owned_flat_u32(
          self.glwe_parameters,
          current_buffer,
        ) {
        Ok(value) => value
        Err(_) => return Err(BlindRotationFailure)
      }
      match current.rotate_negacyclic_into(-switched, workspace.rotated) {
        Ok(_) => ()
        Err(_) => return Err(BlindRotationFailure)
      }
      let rotated = match
        @glwe.glwe_ciphertext_from_owned_flat_u32(
          self.glwe_parameters,
          workspace.rotated,
        ) {
        Ok(value) => value
        Err(_) => return Err(BlindRotationFailure)
      }
      match rotated.sub_into(current, workspace.difference) {
        Ok(_) => ()
        Err(_) => return Err(BlindRotationFailure)
      }
      let difference = match
        @glwe.glwe_ciphertext_from_owned_flat_u32(
          self.glwe_parameters,
          workspace.difference,
        ) {
        Ok(value) => value
        Err(_) => return Err(BlindRotationFailure)
      }
      match self.fourier {
        Some(key) =>
          match
            self.fourier_external_product_add_into(
              key, index, difference, current_buffer, next_buffer,
            ) {
            Ok(_) => ()
            Err(_) => return Err(BlindRotationFailure)
          }
        None => {
          let selected = match self.control(index) {
            Ok(control) =>
              match control.external_product(difference) {
                Ok(value) => value
                Err(_) => return Err(BlindRotationFailure)
              }
            Err(_) => return Err(BootstrapKeyShapeMismatch)
          }
          match current.add_into(selected, next_buffer) {
            Ok(_) => ()
            Err(_) => return Err(BlindRotationFailure)
          }
        }
      }
      active_a = !active_a
    }
  }
  let final_buffer = if active_a {
    workspace.state_a
  } else {
    workspace.state_b
  }
  match
    @glwe.glwe_ciphertext_from_flat_u32(self.glwe_parameters, final_buffer) {
    Ok(value) => Ok(value)
    Err(_) => Err(BlindRotationFailure)
  }
}

///|
fn BootstrapKey::bootstrap_without_keyswitch(
  self : BootstrapKey,
  accumulator : @glwe.GlweCiphertext,
  input : @lwe.LweCiphertext,
) -> Result[@lwe.LweCiphertext, PbsError] {
  let rotated = match self.blind_rotate(accumulator, input) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let workspace = self.workspace.val
  match rotated.sample_extract_into(0, workspace.extracted) {
    Ok(_) =>
      match @params.lwe_dimension(workspace.extracted.length() - 1) {
        Ok(dimension) =>
          match
            @lwe.lwe_ciphertext_from_flat_u32(dimension, workspace.extracted) {
            Ok(value) => Ok(value)
            Err(_) => Err(SampleExtractionFailure)
          }
        Err(_) => Err(SampleExtractionFailure)
      }
    Err(_) => Err(SampleExtractionFailure)
  }
}

///|
fn BootstrapKey::native_programmable_bootstrap(
  self : BootstrapKey,
  context : @provider.PbsContext,
  accumulator : @glwe.GlweCiphertext,
  input : @lwe.LweCiphertext,
) -> Result[@lwe.LweCiphertext, PbsError] {
  let expected_input = match self.order {
    BootstrapKeyswitch => self.input_dimension
    KeyswitchBootstrap => self.key_switch_input
  }
  let output_dimension = match self.order {
    BootstrapKeyswitch => self.key_switch_output
    KeyswitchBootstrap => self.key_switch_input
  }
  if input.parameters() != expected_input ||
    accumulator.parameters() != self.glwe_parameters {
    return Err(InputDimensionMismatch)
  }
  let input_data = input.flat_u32_copy()
  let accumulator_data = accumulator.flat_u32_copy()
  let output = FixedArray::make(output_dimension.value() + 1, 0U)
  match context.evaluate_lut_into(input_data, accumulator_data, output) {
    Ok(_) =>
      match @lwe.lwe_ciphertext_from_owned_flat_u32(output_dimension, output) {
        Ok(value) => Ok(value)
        Err(_) => Err(SampleExtractionFailure)
      }
    Err(_) => Err(BlindRotationFailure)
  }
}

///|
pub fn BootstrapKey::programmable_bootstrap(
  self : BootstrapKey,
  input : @lwe.LweCiphertext,
  lut : BooleanLut,
) -> Result[@lwe.LweCiphertext, PbsError] {
  let accumulator = match lut.accumulator(self.glwe_parameters) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  match self.native_context {
    Some(context) =>
      return self.native_programmable_bootstrap(context, accumulator, input)
    None => ()
  }
  match self.order {
    BootstrapKeyswitch => {
      let extracted = match
        self.bootstrap_without_keyswitch(accumulator, input) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let workspace = self.workspace.val
      let key_switch = match self.key_switch {
        Some(value) => value
        None => return Err(KeyswitchFailure)
      }
      match
        key_switch.apply_into(
          extracted,
          workspace.ksk_result,
          workspace.ksk_digits,
        ) {
        Ok(_) =>
          match
            @lwe.lwe_ciphertext_from_flat_u32(
              self.key_switch_output,
              workspace.ksk_result,
            ) {
            Ok(value) => Ok(value)
            Err(_) => Err(KeyswitchFailure)
          }
        Err(_) => Err(KeyswitchFailure)
      }
    }
    KeyswitchBootstrap => {
      let key_switch = match self.key_switch {
        Some(value) => value
        None => return Err(KeyswitchFailure)
      }
      let switched = match key_switch.apply(input) {
        Ok(value) => value
        Err(_) => return Err(KeyswitchFailure)
      }
      self.bootstrap_without_keyswitch(accumulator, switched)
    }
  }
}

///|
/// Reference programmable bootstrap for an arbitrary anti-periodic torus
/// table. `table[r]` is the output for rotation `r` in `[0, N)`; rotations
/// `r + N` are represented by the negacyclic sign rule.
pub fn BootstrapKey::programmable_bootstrap_table(
  self : BootstrapKey,
  input : @lwe.LweCiphertext,
  table : Array[@torus.Torus32],
) -> Result[@lwe.LweCiphertext, PbsError] {
  if table.length() != self.glwe_parameters.polynomial_size() {
    return Err(InvalidTableLength)
  }
  let accumulator = match @glwe.glwe_trivial(self.glwe_parameters, table) {
    Ok(value) => value
    Err(_) => return Err(InvalidLut)
  }
  match self.native_context {
    Some(context) =>
      return self.native_programmable_bootstrap(context, accumulator, input)
    None => ()
  }
  match self.order {
    BootstrapKeyswitch => {
      let extracted = match
        self.bootstrap_without_keyswitch(accumulator, input) {
        Ok(value) => value
        Err(error) => return Err(error)
      }
      let key_switch = match self.key_switch {
        Some(value) => value
        None => return Err(KeyswitchFailure)
      }
      match key_switch.apply(extracted) {
        Ok(value) => Ok(value)
        Err(_) => Err(KeyswitchFailure)
      }
    }
    KeyswitchBootstrap => {
      let key_switch = match self.key_switch {
        Some(value) => value
        None => return Err(KeyswitchFailure)
      }
      let switched = match key_switch.apply(input) {
        Ok(value) => value
        Err(_) => return Err(KeyswitchFailure)
      }
      self.bootstrap_without_keyswitch(accumulator, switched)
    }
  }
}

///|
test "pbs: Boolean LUT reference preserves both torus outputs" {
  let lut = boolean_lut(
    @torus.Torus32::from_int(-0x2000_0000),
    @torus.Torus32::from_int(0x2000_0000),
  )
  assert_eq(lut.evaluate_reference(false).to_int(), -0x2000_0000)
  assert_eq(lut.evaluate_reference(true).to_int(), 0x2000_0000)
}

///|
test "pbs: typed blind rotation evaluates ID and NOT without a secret key" {
  let input_dimension = @params.lwe_dimension(2).unwrap()
  let input_bits = [true, false]
  let input_key = @lwe.lwe_key_from_binary_secret(input_dimension, input_bits).unwrap()
  let glwe_parameters = @glwe.glwe_parameters(1, 8).unwrap()
  let glwe_key = @glwe.glwe_keygen(
    glwe_parameters,
    @random.test_rng_new(0x504253474C5745),
  )
  let extracted_key = glwe_key.to_extracted_lwe_key().unwrap()
  let decomposition = @params.decomposition_parameters(4, 8).unwrap()
  let noise = @random.gaussian_sigma_3_fixture()
  let key_switch = @keyswitch.keyswitch_keygen(
    extracted_key,
    input_key,
    decomposition,
    noise,
    @random.test_rng_new(0x5042534B534B),
  ).unwrap()
  let ggsw_parameters = @ggsw.ggsw_parameters(glwe_parameters, 4, 8).unwrap()
  let controls : Array[@ggsw.GgswCiphertext] = []
  for index in 0..<input_bits.length() {
    controls.push(
      @ggsw.ggsw_encrypt_boolean(
        ggsw_parameters,
        glwe_key,
        input_bits[index],
        noise,
        @random.test_rng_new(0x50425342534B + index.to_uint64()),
      ).unwrap(),
    )
  }
  let bootstrap_key = bootstrap_key_from_encrypted_parts(
    input_dimension,
    glwe_parameters,
    controls,
    key_switch,
    BootstrapKeyswitch,
  ).unwrap()
  let amplitude = @torus.Torus32::from_int(0x2000_0000)
  for message in [false, true] {
    let ciphertext = input_key.lwe_encrypt_binary(
      message,
      noise,
      @random.test_rng_new(
        if message {
          0x50425354525545
        } else {
          0x50425346414C53
        },
      ),
    )
    let identity = bootstrap_key
      .programmable_bootstrap(
        ciphertext,
        boolean_lut(amplitude.neg(), amplitude),
      )
      .unwrap()
    let negated = bootstrap_key
      .programmable_bootstrap(
        ciphertext,
        boolean_lut(amplitude, amplitude.neg()),
      )
      .unwrap()
    assert_eq(input_key.lwe_decrypt_binary(identity), Ok(message))
    assert_eq(input_key.lwe_decrypt_binary(negated), Ok(!message))
  }
}

///|
test "pbs: key shape failures are explicit and KS-PBS changes key domains" {
  let input_dimension = @params.lwe_dimension(1).unwrap()
  let glwe_parameters = @glwe.glwe_parameters(1, 8).unwrap()
  let decomposition = @params.decomposition_parameters(4, 8).unwrap()
  let input_key = @lwe.lwe_key_from_binary_secret(input_dimension, [true]).unwrap()
  let glwe_key = @glwe.glwe_keygen(
    glwe_parameters,
    @random.test_rng_new(0x5042535348415045),
  )
  let extracted_key = glwe_key.to_extracted_lwe_key().unwrap()
  let key_switch = @keyswitch.keyswitch_keygen(
    extracted_key,
    input_key,
    decomposition,
    @random.gaussian_sigma_3_fixture(),
    @random.test_rng_new(0x5042534B534B32),
  ).unwrap()
  let parameters = @ggsw.ggsw_parameters(glwe_parameters, 4, 8).unwrap()
  let control = @ggsw.ggsw_encrypt_boolean(
    parameters,
    glwe_key,
    true,
    @random.gaussian_sigma_3_fixture(),
    @random.test_rng_new(0x50425342534B32),
  ).unwrap()
  assert_true(
    bootstrap_key_from_encrypted_parts(
      input_dimension,
      glwe_parameters,
      [],
      key_switch,
      BootstrapKeyswitch,
    )
    is Err(BootstrapKeyShapeMismatch),
  )
  let bootstrap_key = bootstrap_key_from_encrypted_parts(
    input_dimension,
    glwe_parameters,
    [control],
    key_switch,
    KeyswitchBootstrap,
  ).unwrap()
  let ciphertext = extracted_key.lwe_encrypt_binary(
    true,
    @random.gaussian_sigma_3_fixture(),
    @random.test_rng_new(0x5042534F52444552),
  )
  let output = bootstrap_key
    .programmable_bootstrap(
      ciphertext,
      boolean_lut(
        @torus.Torus32::from_int(-0x2000_0000),
        @torus.Torus32::from_int(0x2000_0000),
      ),
    )
    .unwrap()
  assert_eq(output.parameters(), extracted_key.parameters())
  assert_eq(extracted_key.lwe_decrypt_binary(output), Ok(true))
}
