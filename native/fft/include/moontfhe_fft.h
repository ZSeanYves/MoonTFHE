#ifndef MOONTFHE_FFT_H
#define MOONTFHE_FFT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct moontfhe_fft_plan moontfhe_fft_plan;

enum moontfhe_fft_status {
  MOONTFHE_FFT_OK = 0,
  MOONTFHE_FFT_NULL_POINTER = 1,
  MOONTFHE_FFT_INVALID_SIZE = 2,
  MOONTFHE_FFT_PANIC = 3,
};

moontfhe_fft_plan *fft_plan_new(uint32_t polynomial_size);
size_t fft_plan_scratch_bytes(const moontfhe_fft_plan *plan);
int32_t negacyclic_mul_u32(const moontfhe_fft_plan *plan,
                           const uint32_t *lhs,
                           const uint32_t *rhs,
                           uint32_t *output,
                           uint8_t *scratch);
int32_t external_product_accumulate_u32(const moontfhe_fft_plan *plan,
                                        const uint32_t *lhs,
                                        const uint32_t *rhs,
                                        uint32_t term_count,
                                        uint32_t *output,
                                        uint8_t *scratch);
void fft_plan_free(moontfhe_fft_plan *plan);

#ifdef __cplusplus
}
#endif

#endif
