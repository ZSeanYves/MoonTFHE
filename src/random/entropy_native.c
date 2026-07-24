#include <moonbit.h>

#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <stdlib.h>
#elif defined(__linux__)
#include <sys/random.h>
#endif

static int entropy_read_all(void *buffer, size_t length) {
#if defined(__APPLE__)
  arc4random_buf(buffer, length);
  return 1;
#elif defined(__linux__)
  unsigned char *cursor = (unsigned char *)buffer;
  size_t remaining = length;
  while (remaining > 0) {
    ssize_t count = getrandom(cursor, remaining, 0);
    if (count <= 0) {
      break;
    }
    cursor += (size_t)count;
    remaining -= (size_t)count;
  }
  if (remaining == 0) {
    return 1;
  }
#endif

  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  unsigned char *cursor_fallback = (unsigned char *)buffer;
  size_t remaining_fallback = length;
  while (remaining_fallback > 0) {
    ssize_t count = read(fd, cursor_fallback, remaining_fallback);
    if (count <= 0) {
      close(fd);
      return 0;
    }
    cursor_fallback += (size_t)count;
    remaining_fallback -= (size_t)count;
  }
  close(fd);
  return 1;
}

MOONBIT_FFI_EXPORT int32_t moonbit_tfhe_entropy_read(moonbit_bytes_t buffer) {
  size_t length = Moonbit_array_length(buffer);
  return entropy_read_all(buffer, length) ? 0 : 1;
}
