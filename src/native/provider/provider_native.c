#include <moonbit.h>

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

typedef struct moontfhe_fft_plan moontfhe_fft_plan;
typedef struct moontfhe_fft_scratch moontfhe_fft_scratch;
typedef struct moontfhe_fourier_bsk moontfhe_fourier_bsk;
typedef struct moontfhe_native_pbs_context moontfhe_native_pbs_context;

extern moontfhe_fft_plan *fft_plan_new(uint32_t polynomial_size);
extern size_t fft_plan_scratch_bytes(const moontfhe_fft_plan *plan,
                                     uint32_t digit_capacity,
                                     uint32_t output_capacity);
extern moontfhe_fft_scratch *fft_scratch_new(const moontfhe_fft_plan *plan,
                                             uint32_t digit_capacity,
                                             uint32_t output_capacity);
extern int32_t negacyclic_mul_u32(const moontfhe_fft_plan *plan,
                                  moontfhe_fft_scratch *scratch,
                                  const uint32_t *lhs,
                                  size_t lhs_len,
                                  const uint32_t *rhs,
                                  size_t rhs_len,
                                  uint32_t *output,
                                  size_t output_len);
extern int32_t batched_glwe_convolution_u32(
    const moontfhe_fft_plan *plan,
    moontfhe_fft_scratch *scratch,
    const uint32_t *lhs,
    const uint32_t *rhs,
    uint32_t term_count,
    uint32_t *output);
extern moontfhe_fourier_bsk *fourier_bsk_new(const moontfhe_fft_plan *plan,
                                             uint32_t ggsw_count,
                                             uint32_t digit_count,
                                             uint32_t output_count);
extern int32_t fourier_bsk_convert(const moontfhe_fft_plan *plan,
                                   moontfhe_fourier_bsk *key,
                                   moontfhe_fft_scratch *scratch,
                                   const uint32_t *coefficients,
                                   size_t coefficient_count);
extern int32_t indexed_ggsw_external_product_u32(
    const moontfhe_fft_plan *plan,
    const moontfhe_fourier_bsk *key,
    moontfhe_fft_scratch *scratch,
    uint32_t ggsw_index,
    const uint32_t *digits,
    size_t digit_count,
    uint32_t *output,
    size_t output_count);
extern int32_t fourier_bsk_external_product_batch(
    const moontfhe_fft_plan *plan,
    const moontfhe_fourier_bsk *key,
    moontfhe_fft_scratch *scratch,
    const uint32_t *ggsw_indices,
    size_t batch_count,
    const uint32_t *digits,
    size_t digit_count,
    uint32_t *output,
    size_t output_count);
extern int32_t fourier_blind_rotation_step(
    const moontfhe_fft_plan *plan,
    const moontfhe_fourier_bsk *key,
    moontfhe_fft_scratch *scratch,
    uint32_t ggsw_index,
    const uint32_t *digits,
    size_t digit_count,
    const uint32_t *addend,
    size_t addend_count,
    uint32_t *output,
    size_t output_count);
extern int32_t fourier_accumulator_add_in_place(uint32_t *accumulator,
                                                size_t accumulator_count,
                                                const uint32_t *addend,
                                                size_t addend_count);
extern int32_t fourier_workspace_reset(moontfhe_fft_scratch *scratch);
extern moontfhe_native_pbs_context *native_pbs_context_new(
    uint32_t polynomial_size, uint32_t input_dimension,
    uint32_t glwe_dimension, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ksk_input_dimension, uint32_t ksk_output_dimension,
    uint32_t ksk_base_log, uint32_t ksk_level, uint32_t order,
    const uint32_t *coefficients, size_t coefficient_count,
    const uint32_t *ksk, size_t ksk_count);
extern moontfhe_native_pbs_context *native_pbs_context_new_empty(
    uint32_t polynomial_size, uint32_t input_dimension,
    uint32_t glwe_dimension, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ksk_input_dimension, uint32_t ksk_output_dimension,
    uint32_t ksk_base_log, uint32_t ksk_level, uint32_t order,
    const uint32_t *ksk, size_t ksk_count);
extern int32_t native_pbs_context_set_control(
    moontfhe_native_pbs_context *context, uint32_t index,
    const uint32_t *coefficients, size_t coefficient_count);
extern int32_t native_pbs_context_ready(
    const moontfhe_native_pbs_context *context);
extern int32_t native_pbs_context_valid(
    const moontfhe_native_pbs_context *context);
extern size_t native_pbs_context_input_size(
    const moontfhe_native_pbs_context *context);
extern size_t native_pbs_context_output_size(
    const moontfhe_native_pbs_context *context);
extern size_t native_pbs_context_coefficient_count(
    const moontfhe_native_pbs_context *context);
extern size_t native_pbs_context_ksk_count(
    const moontfhe_native_pbs_context *context);
extern size_t native_pbs_context_resident_bytes(
    const moontfhe_native_pbs_context *context);
extern size_t native_pbs_context_memory_metric(
    const moontfhe_native_pbs_context *context, uint32_t metric);
extern uint64_t native_pbs_context_measure_allocations(
    moontfhe_native_pbs_context *context, const uint32_t *input,
    size_t input_count, const uint32_t *accumulator,
    size_t accumulator_count, uint32_t *output, size_t output_count,
    size_t iterations);
extern uint64_t native_pbs_context_stage_metric(
    const moontfhe_native_pbs_context *context, uint32_t metric);
extern int32_t native_pbs_evaluate_lut(
    moontfhe_native_pbs_context *context, const uint32_t *input,
    size_t input_count, const uint32_t *accumulator,
    size_t accumulator_count, uint32_t *output, size_t output_count);
extern int32_t native_pbs_context_export_coefficients(
    moontfhe_native_pbs_context *context, uint32_t *output,
    size_t output_count);
extern int32_t native_pbs_context_export_ksk(
    const moontfhe_native_pbs_context *context, uint32_t *output,
    size_t output_count);
extern void native_pbs_context_free(moontfhe_native_pbs_context *context);
extern void fourier_bsk_free(moontfhe_fourier_bsk *key);
extern void fft_scratch_free(moontfhe_fft_scratch *scratch);
extern void fft_plan_free(moontfhe_fft_plan *plan);

extern int32_t aes256_gcm_encrypt(const uint8_t *key,
                                  const uint8_t *nonce,
                                  const uint8_t *aad,
                                  size_t aad_len,
                                  const uint8_t *plaintext,
                                  size_t plaintext_len,
                                  uint8_t *ciphertext,
                                  uint8_t *tag);
extern int32_t aes256_gcm_decrypt(const uint8_t *key,
                                  const uint8_t *nonce,
                                  const uint8_t *aad,
                                  size_t aad_len,
                                  const uint8_t *ciphertext,
                                  size_t ciphertext_len,
                                  const uint8_t *tag,
                                  uint8_t *plaintext);

typedef struct {
  moontfhe_fft_plan *plan;
  moontfhe_fft_scratch *scratch;
  uint32_t polynomial_size;
  uint32_t digit_capacity;
  uint32_t output_capacity;
} moonbit_tfhe_fft_plan;

typedef struct {
  moontfhe_fourier_bsk *key;
  uint32_t ggsw_count;
  uint32_t digit_count;
  uint32_t output_count;
  uint32_t polynomial_size;
} moonbit_tfhe_fourier_bsk;

typedef struct {
  moontfhe_native_pbs_context *context;
  uint32_t input_size;
  uint32_t output_size;
  uint32_t coefficient_count;
  uint32_t ksk_count;
  uint32_t control_count;
  uint32_t control_coefficient_count;
} moonbit_tfhe_pbs_context;

static void moonbit_tfhe_fft_plan_finalize(void *payload) {
  moonbit_tfhe_fft_plan *self = (moonbit_tfhe_fft_plan *)payload;
  if (self->plan != NULL) {
    if (self->scratch != NULL) {
      fft_scratch_free(self->scratch);
      self->scratch = NULL;
    }
    fft_plan_free(self->plan);
    self->plan = NULL;
  }
}

static void moonbit_tfhe_fourier_bsk_finalize(void *payload) {
  moonbit_tfhe_fourier_bsk *self = (moonbit_tfhe_fourier_bsk *)payload;
  if (self->key != NULL) {
    fourier_bsk_free(self->key);
    self->key = NULL;
  }
}

static void moonbit_tfhe_pbs_context_finalize(void *payload) {
  moonbit_tfhe_pbs_context *self = (moonbit_tfhe_pbs_context *)payload;
  if (self->context != NULL) {
    native_pbs_context_free(self->context);
    self->context = NULL;
  }
}

static moonbit_bytes_t status_bytes(int32_t status, int32_t payload_len) {
  moonbit_bytes_t result = moonbit_make_bytes(1 + payload_len, 0);
  result[0] = (uint8_t)status;
  return result;
}

static int checked_mul_size(size_t left, size_t right, size_t *output) {
  if (right != 0 && left > SIZE_MAX / right) {
    return 0;
  }
  *output = left * right;
  return 1;
}

MOONBIT_FFI_EXPORT moonbit_tfhe_fft_plan *
moonbit_tfhe_fft_plan_new(int32_t polynomial_size,
                          int32_t digit_capacity,
                          int32_t output_capacity) {
  moonbit_tfhe_fft_plan *self = (moonbit_tfhe_fft_plan *)
      moonbit_make_external_object(moonbit_tfhe_fft_plan_finalize,
                                   sizeof(moonbit_tfhe_fft_plan));
  self->plan = NULL;
  self->scratch = NULL;
  self->polynomial_size = 0;
  self->digit_capacity = 0;
  self->output_capacity = 0;
  if (polynomial_size <= 0 || digit_capacity <= 0 || output_capacity <= 0) {
    return self;
  }
  self->plan = fft_plan_new((uint32_t)polynomial_size);
  if (self->plan == NULL) {
    return self;
  }
  if (fft_plan_scratch_bytes(self->plan, (uint32_t)digit_capacity,
                             (uint32_t)output_capacity) == 0) {
    fft_plan_free(self->plan);
    self->plan = NULL;
    return self;
  }
  self->scratch = fft_scratch_new(self->plan, (uint32_t)digit_capacity,
                                  (uint32_t)output_capacity);
  if (self->scratch == NULL) {
    fft_plan_free(self->plan);
    self->plan = NULL;
    return self;
  }
  self->polynomial_size = (uint32_t)polynomial_size;
  self->digit_capacity = (uint32_t)digit_capacity;
  self->output_capacity = (uint32_t)output_capacity;
  return self;
}

MOONBIT_FFI_EXPORT int32_t
moonbit_tfhe_fft_plan_valid(moonbit_tfhe_fft_plan *self) {
  return self != NULL && self->plan != NULL && self->scratch != NULL;
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_fft_plan_multiply(
    moonbit_tfhe_fft_plan *self,
    int32_t *left,
    int32_t *right,
    int32_t *output) {
  if (self == NULL || self->plan == NULL || self->scratch == NULL ||
      left == NULL || right == NULL || output == NULL) {
    return 1;
  }
  int32_t left_len = Moonbit_array_length(left);
  int32_t right_len = Moonbit_array_length(right);
  int32_t output_len = Moonbit_array_length(output);
  if (left_len <= 0 || left_len != right_len || left_len != output_len ||
      (uint32_t)left_len != self->polynomial_size) {
    return 2;
  }
  return negacyclic_mul_u32(
      self->plan, self->scratch, (const uint32_t *)left, (size_t)left_len,
      (const uint32_t *)right, (size_t)right_len, (uint32_t *)output,
      (size_t)output_len);
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_fft_plan_batched_convolution(
    moonbit_tfhe_fft_plan *self,
    int32_t *left,
    int32_t *right,
    int32_t term_count,
    int32_t *output) {
  if (self == NULL || self->plan == NULL || self->scratch == NULL ||
      left == NULL || right == NULL || output == NULL || term_count <= 0) {
    return 1;
  }
  size_t expected = 0;
  if (!checked_mul_size((size_t)self->polynomial_size, (size_t)term_count,
                        &expected) ||
      expected > INT32_MAX ||
      (size_t)Moonbit_array_length(left) != expected ||
      (size_t)Moonbit_array_length(right) != expected ||
      Moonbit_array_length(output) != (int32_t)self->polynomial_size) {
    return 2;
  }
  return batched_glwe_convolution_u32(
      self->plan, self->scratch, (const uint32_t *)left,
      (const uint32_t *)right, (uint32_t)term_count, (uint32_t *)output);
}

MOONBIT_FFI_EXPORT moonbit_tfhe_fourier_bsk *
moonbit_tfhe_fourier_bsk_new(moonbit_tfhe_fft_plan *plan,
                             int32_t *coefficients,
                             int32_t ggsw_count,
                             int32_t digit_count,
                             int32_t output_count) {
  moonbit_tfhe_fourier_bsk *self = (moonbit_tfhe_fourier_bsk *)
      moonbit_make_external_object(moonbit_tfhe_fourier_bsk_finalize,
                                   sizeof(moonbit_tfhe_fourier_bsk));
  self->key = NULL;
  self->ggsw_count = 0;
  self->digit_count = 0;
  self->output_count = 0;
  self->polynomial_size = 0;
  if (plan == NULL || plan->plan == NULL || plan->scratch == NULL ||
      coefficients == NULL || ggsw_count <= 0 || digit_count <= 0 ||
      output_count <= 0 || (uint32_t)digit_count > plan->digit_capacity ||
      (uint32_t)output_count > plan->output_capacity) {
    return self;
  }
  size_t expected = 0;
  if (!checked_mul_size((size_t)ggsw_count, (size_t)digit_count, &expected) ||
      !checked_mul_size(expected, (size_t)output_count, &expected) ||
      !checked_mul_size(expected, (size_t)plan->polynomial_size, &expected) ||
      expected > INT32_MAX) {
    return self;
  }
  if ((size_t)Moonbit_array_length(coefficients) != expected) {
    return self;
  }
  self->key = fourier_bsk_new(plan->plan, (uint32_t)ggsw_count,
                              (uint32_t)digit_count, (uint32_t)output_count);
  if (self->key == NULL) {
    return self;
  }
  int32_t status = fourier_bsk_convert(
      plan->plan, self->key, plan->scratch, (const uint32_t *)coefficients,
      expected);
  if (status != 0) {
    fourier_bsk_free(self->key);
    self->key = NULL;
    return self;
  }
  self->ggsw_count = (uint32_t)ggsw_count;
  self->digit_count = (uint32_t)digit_count;
  self->output_count = (uint32_t)output_count;
  self->polynomial_size = plan->polynomial_size;
  return self;
}

MOONBIT_FFI_EXPORT int32_t
moonbit_tfhe_fourier_bsk_valid(moonbit_tfhe_fourier_bsk *self) {
  return self != NULL && self->key != NULL;
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_fourier_bsk_external_product(
    moonbit_tfhe_fft_plan *plan,
    moonbit_tfhe_fourier_bsk *key,
    int32_t ggsw_index,
    int32_t *digits,
    int32_t *output) {
  if (plan == NULL || plan->plan == NULL || plan->scratch == NULL ||
      key == NULL || key->key == NULL || digits == NULL || output == NULL ||
      ggsw_index < 0 || (uint32_t)ggsw_index >= key->ggsw_count) {
    return 1;
  }
  size_t expected_digits = 0;
  size_t expected_output = 0;
  if (!checked_mul_size((size_t)key->digit_count,
                        (size_t)key->polynomial_size, &expected_digits) ||
      !checked_mul_size((size_t)key->output_count,
                        (size_t)key->polynomial_size, &expected_output) ||
      expected_digits > INT32_MAX || expected_output > INT32_MAX) {
    return 2;
  }
  if ((size_t)Moonbit_array_length(digits) != expected_digits ||
      (size_t)Moonbit_array_length(output) != expected_output) {
    return 2;
  }
  return indexed_ggsw_external_product_u32(
      plan->plan, key->key, plan->scratch, (uint32_t)ggsw_index,
      (const uint32_t *)digits, expected_digits, (uint32_t *)output,
      expected_output);
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_fourier_bsk_external_product_batch(
    moonbit_tfhe_fft_plan *plan,
    moonbit_tfhe_fourier_bsk *key,
    int32_t *ggsw_indices,
    int32_t *digits,
    int32_t *output) {
  if (plan == NULL || plan->plan == NULL || plan->scratch == NULL ||
      key == NULL || key->key == NULL || ggsw_indices == NULL ||
      digits == NULL || output == NULL) {
    return 1;
  }
  int32_t batch_count = Moonbit_array_length(ggsw_indices);
  if (batch_count <= 0) {
    return 2;
  }
  size_t digits_per_batch = 0;
  size_t output_per_batch = 0;
  size_t expected_digits = 0;
  size_t expected_output = 0;
  if (!checked_mul_size((size_t)key->digit_count,
                        (size_t)key->polynomial_size, &digits_per_batch) ||
      !checked_mul_size((size_t)key->output_count,
                        (size_t)key->polynomial_size, &output_per_batch) ||
      !checked_mul_size((size_t)batch_count, digits_per_batch,
                        &expected_digits) ||
      !checked_mul_size((size_t)batch_count, output_per_batch,
                        &expected_output) ||
      expected_digits > INT32_MAX || expected_output > INT32_MAX ||
      (size_t)Moonbit_array_length(digits) != expected_digits ||
      (size_t)Moonbit_array_length(output) != expected_output) {
    return 2;
  }
  return fourier_bsk_external_product_batch(
      plan->plan, key->key, plan->scratch, (const uint32_t *)ggsw_indices,
      (size_t)batch_count, (const uint32_t *)digits, expected_digits,
      (uint32_t *)output, expected_output);
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_fourier_blind_rotation_step(
    moonbit_tfhe_fft_plan *plan,
    moonbit_tfhe_fourier_bsk *key,
    int32_t ggsw_index,
    int32_t *digits,
    int32_t *addend,
    int32_t *output) {
  if (plan == NULL || plan->plan == NULL || plan->scratch == NULL ||
      key == NULL || key->key == NULL || digits == NULL || addend == NULL ||
      output == NULL || ggsw_index < 0 ||
      (uint32_t)ggsw_index >= key->ggsw_count) {
    return 1;
  }
  size_t expected_digits = 0;
  size_t expected_output = 0;
  if (!checked_mul_size((size_t)key->digit_count,
                        (size_t)key->polynomial_size, &expected_digits) ||
      !checked_mul_size((size_t)key->output_count,
                        (size_t)key->polynomial_size, &expected_output) ||
      expected_digits > INT32_MAX || expected_output > INT32_MAX ||
      (size_t)Moonbit_array_length(digits) != expected_digits ||
      (size_t)Moonbit_array_length(addend) != expected_output ||
      (size_t)Moonbit_array_length(output) != expected_output) {
    return 2;
  }
  return fourier_blind_rotation_step(
      plan->plan, key->key, plan->scratch, (uint32_t)ggsw_index,
      (const uint32_t *)digits, expected_digits, (const uint32_t *)addend,
      expected_output, (uint32_t *)output, expected_output);
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_fourier_accumulator_add_in_place(
    int32_t *accumulator,
    int32_t *addend) {
  if (accumulator == NULL || addend == NULL) {
    return 1;
  }
  int32_t accumulator_count = Moonbit_array_length(accumulator);
  int32_t addend_count = Moonbit_array_length(addend);
  if (accumulator_count < 0 || accumulator_count != addend_count) {
    return 2;
  }
  return fourier_accumulator_add_in_place(
      (uint32_t *)accumulator, (size_t)accumulator_count,
      (const uint32_t *)addend, (size_t)addend_count);
}

MOONBIT_FFI_EXPORT int32_t
moonbit_tfhe_fourier_workspace_reset(moonbit_tfhe_fft_plan *plan) {
  if (plan == NULL || plan->plan == NULL || plan->scratch == NULL) {
    return 1;
  }
  return fourier_workspace_reset(plan->scratch);
}

MOONBIT_FFI_EXPORT moonbit_tfhe_pbs_context *moonbit_tfhe_pbs_context_new(
    int32_t polynomial_size, int32_t input_dimension,
    int32_t glwe_dimension, int32_t pbs_base_log, int32_t pbs_level,
    int32_t ksk_input_dimension, int32_t ksk_output_dimension,
    int32_t ksk_base_log, int32_t ksk_level, int32_t order,
    int32_t *coefficients, int32_t *ksk) {
  moonbit_tfhe_pbs_context *self = (moonbit_tfhe_pbs_context *)
      moonbit_make_external_object(moonbit_tfhe_pbs_context_finalize,
                                   sizeof(moonbit_tfhe_pbs_context));
  self->context = NULL;
  self->input_size = 0;
  self->output_size = 0;
  self->coefficient_count = 0;
  self->ksk_count = 0;
  self->control_count = 0;
  self->control_coefficient_count = 0;
  if (polynomial_size <= 0 || input_dimension <= 0 || glwe_dimension <= 0 ||
      pbs_base_log <= 0 || pbs_level <= 0 || ksk_input_dimension <= 0 ||
      ksk_output_dimension <= 0 || ksk_base_log <= 0 || ksk_level <= 0 ||
      order < 0 || order > 1 || coefficients == NULL || ksk == NULL) {
    return self;
  }
  int32_t coefficient_count = Moonbit_array_length(coefficients);
  int32_t ksk_count = Moonbit_array_length(ksk);
  if (coefficient_count <= 0 || ksk_count <= 0) {
    return self;
  }
  self->context = native_pbs_context_new(
      (uint32_t)polynomial_size, (uint32_t)input_dimension,
      (uint32_t)glwe_dimension, (uint32_t)pbs_base_log, (uint32_t)pbs_level,
      (uint32_t)ksk_input_dimension, (uint32_t)ksk_output_dimension,
      (uint32_t)ksk_base_log, (uint32_t)ksk_level, (uint32_t)order,
      (const uint32_t *)coefficients, (size_t)coefficient_count,
      (const uint32_t *)ksk, (size_t)ksk_count);
  if (self->context == NULL) {
    return self;
  }
  size_t input_size = native_pbs_context_input_size(self->context);
  size_t output_size = native_pbs_context_output_size(self->context);
  size_t exported_coefficients =
      native_pbs_context_coefficient_count(self->context);
  size_t exported_ksk = native_pbs_context_ksk_count(self->context);
  if (input_size > INT32_MAX || output_size > INT32_MAX ||
      exported_coefficients > INT32_MAX || exported_ksk > INT32_MAX) {
    native_pbs_context_free(self->context);
    self->context = NULL;
    return self;
  }
  self->input_size = (uint32_t)input_size;
  self->output_size = (uint32_t)output_size;
  self->coefficient_count = (uint32_t)exported_coefficients;
  self->ksk_count = (uint32_t)exported_ksk;
  self->control_count = (uint32_t)input_dimension;
  self->control_coefficient_count =
      (uint32_t)(exported_coefficients / (size_t)input_dimension);
  return self;
}

MOONBIT_FFI_EXPORT moonbit_tfhe_pbs_context *
moonbit_tfhe_pbs_context_new_empty(
    int32_t polynomial_size, int32_t input_dimension,
    int32_t glwe_dimension, int32_t pbs_base_log, int32_t pbs_level,
    int32_t ksk_input_dimension, int32_t ksk_output_dimension,
    int32_t ksk_base_log, int32_t ksk_level, int32_t order,
    int32_t *ksk) {
  moonbit_tfhe_pbs_context *self = (moonbit_tfhe_pbs_context *)
      moonbit_make_external_object(moonbit_tfhe_pbs_context_finalize,
                                   sizeof(moonbit_tfhe_pbs_context));
  self->context = NULL;
  self->input_size = 0;
  self->output_size = 0;
  self->coefficient_count = 0;
  self->ksk_count = 0;
  self->control_count = 0;
  self->control_coefficient_count = 0;
  if (polynomial_size <= 0 || input_dimension <= 0 ||
      glwe_dimension <= 0 || pbs_base_log <= 0 || pbs_level <= 0 ||
      ksk_input_dimension <= 0 || ksk_output_dimension <= 0 ||
      ksk_base_log <= 0 || ksk_level <= 0 || order < 0 || order > 1 ||
      ksk == NULL) {
    return self;
  }
  int32_t ksk_count = Moonbit_array_length(ksk);
  if (ksk_count <= 0) {
    return self;
  }
  self->context = native_pbs_context_new_empty(
      (uint32_t)polynomial_size, (uint32_t)input_dimension,
      (uint32_t)glwe_dimension, (uint32_t)pbs_base_log,
      (uint32_t)pbs_level, (uint32_t)ksk_input_dimension,
      (uint32_t)ksk_output_dimension, (uint32_t)ksk_base_log,
      (uint32_t)ksk_level, (uint32_t)order, (const uint32_t *)ksk,
      (size_t)ksk_count);
  if (self->context == NULL) {
    return self;
  }
  size_t input_size = native_pbs_context_input_size(self->context);
  size_t output_size = native_pbs_context_output_size(self->context);
  size_t exported_coefficients =
      native_pbs_context_coefficient_count(self->context);
  size_t exported_ksk = native_pbs_context_ksk_count(self->context);
  if (input_size > INT32_MAX || output_size > INT32_MAX ||
      exported_coefficients > INT32_MAX || exported_ksk > INT32_MAX ||
      exported_coefficients % (size_t)input_dimension != 0) {
    native_pbs_context_free(self->context);
    self->context = NULL;
    return self;
  }
  self->input_size = (uint32_t)input_size;
  self->output_size = (uint32_t)output_size;
  self->coefficient_count = (uint32_t)exported_coefficients;
  self->ksk_count = (uint32_t)exported_ksk;
  self->control_count = (uint32_t)input_dimension;
  self->control_coefficient_count =
      (uint32_t)(exported_coefficients / (size_t)input_dimension);
  return self;
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_pbs_context_set_control(
    moonbit_tfhe_pbs_context *self, int32_t index,
    int32_t *coefficients) {
  if (self == NULL || self->context == NULL || coefficients == NULL ||
      index < 0 || (uint32_t)index >= self->control_count) {
    return 1;
  }
  int32_t count = Moonbit_array_length(coefficients);
  if (count < 0 || (uint32_t)count != self->control_coefficient_count) {
    return 2;
  }
  return native_pbs_context_set_control(
      self->context, (uint32_t)index, (const uint32_t *)coefficients,
      (size_t)count);
}

MOONBIT_FFI_EXPORT int32_t
moonbit_tfhe_pbs_context_ready(moonbit_tfhe_pbs_context *self) {
  return self != NULL && self->context != NULL &&
         native_pbs_context_ready(self->context) != 0;
}

MOONBIT_FFI_EXPORT int32_t
moonbit_tfhe_pbs_context_valid(moonbit_tfhe_pbs_context *self) {
  return self != NULL && self->context != NULL &&
         native_pbs_context_valid(self->context) != 0;
}

MOONBIT_FFI_EXPORT int64_t
moonbit_tfhe_pbs_context_resident_bytes(moonbit_tfhe_pbs_context *self) {
  if (self == NULL || self->context == NULL) {
    return 0;
  }
  size_t bytes = native_pbs_context_resident_bytes(self->context);
  return bytes > INT64_MAX ? 0 : (int64_t)bytes;
}

MOONBIT_FFI_EXPORT int64_t moonbit_tfhe_pbs_context_memory_metric(
    moonbit_tfhe_pbs_context *self, int32_t metric) {
  if (self == NULL || self->context == NULL || metric < 0 || metric > 3) {
    return 0;
  }
  size_t bytes = native_pbs_context_memory_metric(
      self->context, (uint32_t)metric);
  return bytes > INT64_MAX ? 0 : (int64_t)bytes;
}

MOONBIT_FFI_EXPORT int64_t moonbit_tfhe_pbs_context_measure_allocations(
    moonbit_tfhe_pbs_context *self, int32_t *input,
    int32_t *accumulator, int32_t *output, int32_t iterations) {
  if (self == NULL || self->context == NULL || input == NULL ||
      accumulator == NULL || output == NULL || iterations <= 0) {
    return -1;
  }
  int32_t input_count = Moonbit_array_length(input);
  int32_t accumulator_count = Moonbit_array_length(accumulator);
  int32_t output_count = Moonbit_array_length(output);
  if (input_count < 0 || accumulator_count <= 0 || output_count < 0 ||
      (uint32_t)input_count != self->input_size ||
      (uint32_t)output_count != self->output_size) {
    return -1;
  }
  uint64_t allocations = native_pbs_context_measure_allocations(
      self->context, (const uint32_t *)input, (size_t)input_count,
      (const uint32_t *)accumulator, (size_t)accumulator_count,
      (uint32_t *)output, (size_t)output_count, (size_t)iterations);
  return allocations == UINT64_MAX || allocations > INT64_MAX
             ? -1
             : (int64_t)allocations;
}

MOONBIT_FFI_EXPORT int64_t moonbit_tfhe_pbs_context_stage_metric(
    moonbit_tfhe_pbs_context *self, int32_t metric) {
  if (self == NULL || self->context == NULL || metric < 0 || metric > 4) {
    return 0;
  }
  uint64_t value = native_pbs_context_stage_metric(
      self->context, (uint32_t)metric);
  return value > INT64_MAX ? INT64_MAX : (int64_t)value;
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_pbs_evaluate_lut(
    moonbit_tfhe_pbs_context *self, int32_t *input,
    int32_t *accumulator, int32_t *output) {
  if (self == NULL || self->context == NULL || input == NULL ||
      accumulator == NULL || output == NULL) {
    return 1;
  }
  int32_t input_count = Moonbit_array_length(input);
  int32_t accumulator_count = Moonbit_array_length(accumulator);
  int32_t output_count = Moonbit_array_length(output);
  if (input_count < 0 || accumulator_count <= 0 || output_count < 0 ||
      (uint32_t)input_count != self->input_size ||
      (uint32_t)output_count != self->output_size) {
    return 2;
  }
  return native_pbs_evaluate_lut(
      self->context, (const uint32_t *)input, (size_t)input_count,
      (const uint32_t *)accumulator, (size_t)accumulator_count,
      (uint32_t *)output, (size_t)output_count);
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_pbs_context_export_coefficients(
    moonbit_tfhe_pbs_context *self, int32_t *output) {
  if (self == NULL || self->context == NULL || output == NULL) {
    return 1;
  }
  int32_t count = Moonbit_array_length(output);
  if (count < 0 || (uint32_t)count != self->coefficient_count) {
    return 2;
  }
  return native_pbs_context_export_coefficients(
      self->context, (uint32_t *)output, (size_t)count);
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_pbs_context_export_ksk(
    moonbit_tfhe_pbs_context *self, int32_t *output) {
  if (self == NULL || self->context == NULL || output == NULL) {
    return 1;
  }
  int32_t count = Moonbit_array_length(output);
  if (count < 0 || (uint32_t)count != self->ksk_count) {
    return 2;
  }
  return native_pbs_context_export_ksk(
      self->context, (uint32_t *)output, (size_t)count);
}

MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_tfhe_aes256_gcm_encrypt(
    moonbit_bytes_t key,
    moonbit_bytes_t nonce,
    moonbit_bytes_t aad,
    moonbit_bytes_t plaintext) {
  if (key == NULL || nonce == NULL || aad == NULL || plaintext == NULL ||
      Moonbit_array_length(key) != 32 || Moonbit_array_length(nonce) != 12) {
    return status_bytes(1, 0);
  }
  int32_t aad_len = Moonbit_array_length(aad);
  int32_t plaintext_len = Moonbit_array_length(plaintext);
  if (plaintext_len > INT32_MAX - 16) {
    return status_bytes(1, 0);
  }
  moonbit_bytes_t result = status_bytes(0, plaintext_len + 16);
  int32_t status = aes256_gcm_encrypt(
      key, nonce, aad, (size_t)aad_len, plaintext, (size_t)plaintext_len,
      result + 1, result + 1 + plaintext_len);
  result[0] = (uint8_t)status;
  return result;
}

MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_tfhe_aes256_gcm_decrypt(
    moonbit_bytes_t key,
    moonbit_bytes_t nonce,
    moonbit_bytes_t aad,
    moonbit_bytes_t sealed) {
  if (key == NULL || nonce == NULL || aad == NULL || sealed == NULL ||
      Moonbit_array_length(key) != 32 || Moonbit_array_length(nonce) != 12 ||
      Moonbit_array_length(sealed) < 16) {
    return status_bytes(1, 0);
  }
  int32_t aad_len = Moonbit_array_length(aad);
  int32_t sealed_len = Moonbit_array_length(sealed);
  int32_t ciphertext_len = sealed_len - 16;
  moonbit_bytes_t result = status_bytes(0, ciphertext_len);
  int32_t status = aes256_gcm_decrypt(
      key, nonce, aad, (size_t)aad_len, sealed, (size_t)ciphertext_len,
      sealed + ciphertext_len, result + 1);
  result[0] = (uint8_t)status;
  return result;
}
