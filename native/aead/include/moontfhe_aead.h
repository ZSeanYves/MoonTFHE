#ifndef MOONTFHE_AEAD_H
#define MOONTFHE_AEAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum moontfhe_aead_status {
  MOONTFHE_AEAD_OK = 0,
  MOONTFHE_AEAD_NULL_POINTER = 1,
  MOONTFHE_AEAD_AUTHENTICATION_FAILED = 2,
  MOONTFHE_AEAD_PANIC = 3,
};

int32_t aes256_gcm_encrypt(const uint8_t *key,
                           const uint8_t *nonce,
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *plaintext,
                           size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t *tag);

int32_t aes256_gcm_decrypt(const uint8_t *key,
                           const uint8_t *nonce,
                           const uint8_t *aad,
                           size_t aad_len,
                           const uint8_t *ciphertext,
                           size_t ciphertext_len,
                           const uint8_t *tag,
                           uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
