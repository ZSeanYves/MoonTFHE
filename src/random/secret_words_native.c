#include <moonbit.h>

#include <stdint.h>
#include <stdlib.h>

typedef struct {
  uint32_t *words;
  int32_t length;
  int32_t destroyed;
} moontfhe_secret_words;

static void secret_words_zero(volatile uint32_t *words, int32_t length) {
  if (words == NULL || length <= 0) {
    return;
  }
  for (int32_t index = 0; index < length; index++) {
    words[index] = 0;
  }
}

static void secret_words_finalize(void *payload) {
  moontfhe_secret_words *value = (moontfhe_secret_words *)payload;
  if (value == NULL) {
    return;
  }
  secret_words_zero(value->words, value->length);
  free(value->words);
  value->words = NULL;
  value->length = 0;
  value->destroyed = 1;
}

MOONBIT_FFI_EXPORT moontfhe_secret_words *moonbit_tfhe_secret_words_new(
    int32_t *words) {
  int32_t length = words == NULL ? 0 : Moonbit_array_length(words);
  moontfhe_secret_words *value =
      (moontfhe_secret_words *)moonbit_make_external_object(
          secret_words_finalize, sizeof(moontfhe_secret_words));
  value->words = NULL;
  value->length = length;
  value->destroyed = 0;
  if (length > 0) {
    value->words = (uint32_t *)calloc((size_t)length, sizeof(uint32_t));
    if (value->words == NULL) {
      value->length = 0;
      value->destroyed = 1;
      return value;
    }
    for (int32_t index = 0; index < length; index++) {
      value->words[index] = (uint32_t)words[index];
    }
  }
  return value;
}

MOONBIT_FFI_EXPORT uint32_t moonbit_tfhe_secret_words_get(
    moontfhe_secret_words *value, int32_t index) {
  if (value == NULL || value->destroyed || value->words == NULL ||
      index < 0 || index >= value->length) {
    return 0;
  }
  return value->words[index];
}

MOONBIT_FFI_EXPORT void moonbit_tfhe_secret_words_set(
    moontfhe_secret_words *value, int32_t index, uint32_t word) {
  if (value == NULL || value->destroyed || value->words == NULL ||
      index < 0 || index >= value->length) {
    return;
  }
  value->words[index] = word;
}

MOONBIT_FFI_EXPORT void moonbit_tfhe_secret_words_destroy(
    moontfhe_secret_words *value) {
  if (value == NULL || value->destroyed) {
    return;
  }
  secret_words_zero(value->words, value->length);
  free(value->words);
  value->words = NULL;
  value->length = 0;
  value->destroyed = 1;
}
