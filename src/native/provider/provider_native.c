#include <moonbit.h>

#include <stdint.h>
#include <stdlib.h>

typedef struct moontfhe_fft_plan moontfhe_fft_plan;

extern moontfhe_fft_plan *fft_plan_new(uint32_t polynomial_size);
extern size_t fft_plan_scratch_bytes(const moontfhe_fft_plan *plan);
extern int32_t negacyclic_mul_u32(const moontfhe_fft_plan *plan,
                                  const uint32_t *lhs,
                                  const uint32_t *rhs,
                                  uint32_t *output,
                                  uint8_t *scratch);
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
  uint8_t *scratch;
  size_t scratch_len;
  uint32_t polynomial_size;
} moonbit_tfhe_fft_plan;

static void moonbit_tfhe_fft_plan_finalize(void *payload) {
  moonbit_tfhe_fft_plan *self = (moonbit_tfhe_fft_plan *)payload;
  if (self->plan != NULL) {
    fft_plan_free(self->plan);
    self->plan = NULL;
  }
  free(self->scratch);
  self->scratch = NULL;
  self->scratch_len = 0;
}

static uint32_t load_u32_le(const uint8_t *bytes) {
  return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void store_u32_le(uint8_t *bytes, uint32_t value) {
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8);
  bytes[2] = (uint8_t)(value >> 16);
  bytes[3] = (uint8_t)(value >> 24);
}

static moonbit_bytes_t status_bytes(int32_t status, int32_t payload_len) {
  moonbit_bytes_t result = moonbit_make_bytes(1 + payload_len, 0);
  result[0] = (uint8_t)status;
  return result;
}

MOONBIT_FFI_EXPORT moonbit_tfhe_fft_plan *
moonbit_tfhe_fft_plan_new(int32_t polynomial_size) {
  moonbit_tfhe_fft_plan *self = (moonbit_tfhe_fft_plan *)
      moonbit_make_external_object(moonbit_tfhe_fft_plan_finalize,
                                   sizeof(moonbit_tfhe_fft_plan));
  self->plan = NULL;
  self->scratch = NULL;
  self->scratch_len = 0;
  self->polynomial_size = 0;
  if (polynomial_size <= 0) {
    return self;
  }
  self->plan = fft_plan_new((uint32_t)polynomial_size);
  if (self->plan == NULL) {
    return self;
  }
  self->scratch_len = fft_plan_scratch_bytes(self->plan);
  self->scratch = (uint8_t *)malloc(self->scratch_len);
  if (self->scratch == NULL) {
    fft_plan_free(self->plan);
    self->plan = NULL;
    self->scratch_len = 0;
    return self;
  }
  self->polynomial_size = (uint32_t)polynomial_size;
  return self;
}

MOONBIT_FFI_EXPORT int32_t
moonbit_tfhe_fft_plan_valid(moonbit_tfhe_fft_plan *self) {
  return self != NULL && self->plan != NULL && self->scratch != NULL;
}

MOONBIT_FFI_EXPORT moonbit_bytes_t moonbit_tfhe_fft_plan_multiply(
    moonbit_tfhe_fft_plan *self,
    moonbit_bytes_t left,
    moonbit_bytes_t right) {
  if (self == NULL || self->plan == NULL || left == NULL || right == NULL) {
    return status_bytes(1, 0);
  }
  int32_t left_len = Moonbit_array_length(left);
  int32_t right_len = Moonbit_array_length(right);
  if (left_len <= 0 || left_len != right_len || left_len % 4 != 0 ||
      (uint32_t)(left_len / 4) != self->polynomial_size) {
    return status_bytes(2, 0);
  }
  size_t count = self->polynomial_size;
  uint32_t *lhs = (uint32_t *)malloc(count * sizeof(uint32_t));
  uint32_t *rhs = (uint32_t *)malloc(count * sizeof(uint32_t));
  uint32_t *output = (uint32_t *)malloc(count * sizeof(uint32_t));
  if (lhs == NULL || rhs == NULL || output == NULL) {
    free(lhs);
    free(rhs);
    free(output);
    return status_bytes(3, 0);
  }
  for (size_t index = 0; index < count; ++index) {
    lhs[index] = load_u32_le(left + 4 * index);
    rhs[index] = load_u32_le(right + 4 * index);
  }
  int32_t status = negacyclic_mul_u32(
      self->plan, lhs, rhs, output, self->scratch);
  moonbit_bytes_t result = status_bytes(status, status == 0 ? left_len : 0);
  if (status == 0) {
    for (size_t index = 0; index < count; ++index) {
      store_u32_le(result + 1 + 4 * index, output[index]);
    }
  }
  free(lhs);
  free(rhs);
  free(output);
  return result;
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
