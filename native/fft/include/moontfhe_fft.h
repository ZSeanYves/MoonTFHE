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

enum moontfhe_fft_status {
  MOONTFHE_FFT_OK = 0,
  MOONTFHE_FFT_NULL_POINTER = 1,
  MOONTFHE_FFT_INVALID_SIZE = 2,
  MOONTFHE_FFT_PANIC = 3,
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
void fourier_bsk_free(moontfhe_fourier_bsk *key);
void fft_scratch_free(moontfhe_fft_scratch *scratch);
void fft_plan_free(moontfhe_fft_plan *plan);

#ifdef __cplusplus
}
#endif

#endif
