#ifndef MOONTFHE_FFT_H
#define MOONTFHE_FFT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct moontfhe_fft_plan moontfhe_fft_plan;
typedef struct moontfhe_fft_scratch moontfhe_fft_scratch;
typedef struct moontfhe_fourier_bsk moontfhe_fourier_bsk;
typedef struct moontfhe_native_pbs_context moontfhe_native_pbs_context;

enum moontfhe_fft_status {
  MOONTFHE_FFT_OK = 0,
  MOONTFHE_FFT_NULL_POINTER = 1,
  MOONTFHE_FFT_INVALID_SIZE = 2,
  MOONTFHE_FFT_PANIC = 3,
  MOONTFHE_FFT_BUSY = 4,
};

moontfhe_fft_plan *fft_plan_new(uint32_t polynomial_size);
size_t fft_plan_scratch_bytes(const moontfhe_fft_plan *plan,
                              uint32_t digit_capacity,
                              uint32_t output_capacity);
moontfhe_fft_scratch *fft_scratch_new(const moontfhe_fft_plan *plan,
                                      uint32_t digit_capacity,
                                      uint32_t output_capacity);
int32_t negacyclic_mul_u32(const moontfhe_fft_plan *plan,
                           moontfhe_fft_scratch *scratch,
                           const uint32_t *lhs,
                           size_t lhs_len,
                           const uint32_t *rhs,
                           size_t rhs_len,
                           uint32_t *output,
                           size_t output_len);
int32_t batched_glwe_convolution_u32(const moontfhe_fft_plan *plan,
                                     moontfhe_fft_scratch *scratch,
                                     const uint32_t *lhs,
                                     const uint32_t *rhs,
                                     uint32_t term_count,
                                     uint32_t *output);
moontfhe_fourier_bsk *fourier_bsk_new(const moontfhe_fft_plan *plan,
                                      uint32_t ggsw_count,
                                      uint32_t digit_count,
                                      uint32_t output_count);
int32_t fourier_bsk_convert(const moontfhe_fft_plan *plan,
                            moontfhe_fourier_bsk *key,
                            moontfhe_fft_scratch *scratch,
                            const uint32_t *coefficients,
                            size_t coefficient_count);
int32_t indexed_ggsw_external_product_u32(const moontfhe_fft_plan *plan,
                                          const moontfhe_fourier_bsk *key,
                                          moontfhe_fft_scratch *scratch,
                                          uint32_t ggsw_index,
                                          const uint32_t *digits,
                                          size_t digit_count,
                                          uint32_t *output,
                                          size_t output_count);
int32_t fourier_bsk_external_product_into(const moontfhe_fft_plan *plan,
                                          const moontfhe_fourier_bsk *key,
                                          moontfhe_fft_scratch *scratch,
                                          uint32_t ggsw_index,
                                          const uint32_t *digits,
                                          size_t digit_count,
                                          uint32_t *output,
                                          size_t output_count);
int32_t fourier_bsk_external_product_batch(const moontfhe_fft_plan *plan,
                                           const moontfhe_fourier_bsk *key,
                                           moontfhe_fft_scratch *scratch,
                                           const uint32_t *ggsw_indices,
                                           size_t batch_count,
                                           const uint32_t *digits,
                                           size_t digit_count,
                                           uint32_t *output,
                                           size_t output_count);
int32_t fourier_blind_rotation_step(const moontfhe_fft_plan *plan,
                                    const moontfhe_fourier_bsk *key,
                                    moontfhe_fft_scratch *scratch,
                                    uint32_t ggsw_index,
                                    const uint32_t *digits,
                                    size_t digit_count,
                                    const uint32_t *addend,
                                    size_t addend_count,
                                    uint32_t *output,
                                    size_t output_count);
int32_t fourier_accumulator_add_in_place(uint32_t *accumulator,
                                         size_t accumulator_count,
                                         const uint32_t *addend,
                                         size_t addend_count);
int32_t fourier_workspace_reset(moontfhe_fft_scratch *scratch);
moontfhe_native_pbs_context *native_pbs_context_new(
    uint32_t polynomial_size, uint32_t input_dimension,
    uint32_t glwe_dimension, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ksk_input_dimension, uint32_t ksk_output_dimension,
    uint32_t ksk_base_log, uint32_t ksk_level, uint32_t order,
    const uint32_t *coefficients, size_t coefficient_count,
    const uint32_t *ksk, size_t ksk_count);
moontfhe_native_pbs_context *native_pbs_context_new_empty(
    uint32_t polynomial_size, uint32_t input_dimension,
    uint32_t glwe_dimension, uint32_t pbs_base_log, uint32_t pbs_level,
    uint32_t ksk_input_dimension, uint32_t ksk_output_dimension,
    uint32_t ksk_base_log, uint32_t ksk_level, uint32_t order,
    const uint32_t *ksk, size_t ksk_count);
int32_t native_pbs_context_set_control(
    moontfhe_native_pbs_context *context, uint32_t index,
    const uint32_t *coefficients, size_t coefficient_count);
int32_t native_pbs_context_ready(
    const moontfhe_native_pbs_context *context);
int32_t native_pbs_context_valid(const moontfhe_native_pbs_context *context);
size_t native_pbs_context_input_size(const moontfhe_native_pbs_context *context);
size_t native_pbs_context_output_size(const moontfhe_native_pbs_context *context);
size_t native_pbs_context_coefficient_count(
    const moontfhe_native_pbs_context *context);
size_t native_pbs_context_ksk_count(
    const moontfhe_native_pbs_context *context);
size_t native_pbs_context_resident_bytes(
    const moontfhe_native_pbs_context *context);
size_t native_pbs_context_memory_metric(
    const moontfhe_native_pbs_context *context, uint32_t metric);
uint64_t native_pbs_context_measure_allocations(
    moontfhe_native_pbs_context *context, const uint32_t *input,
    size_t input_count, const uint32_t *accumulator,
    size_t accumulator_count, uint32_t *output, size_t output_count,
    size_t iterations);
uint64_t native_pbs_context_stage_metric(
    const moontfhe_native_pbs_context *context, uint32_t metric);
int32_t native_pbs_evaluate_lut(moontfhe_native_pbs_context *context,
                                const uint32_t *input, size_t input_count,
                                const uint32_t *accumulator,
                                size_t accumulator_count, uint32_t *output,
                                size_t output_count);
int32_t native_pbs_context_export_coefficients(
    moontfhe_native_pbs_context *context, uint32_t *output,
    size_t output_count);
int32_t native_pbs_context_export_ksk(
    const moontfhe_native_pbs_context *context, uint32_t *output,
    size_t output_count);
void native_pbs_context_free(moontfhe_native_pbs_context *context);
void fourier_bsk_free(moontfhe_fourier_bsk *key);
void fft_scratch_free(moontfhe_fft_scratch *scratch);
void fft_plan_free(moontfhe_fft_plan *plan);

#ifdef __cplusplus
}
#endif

#endif
