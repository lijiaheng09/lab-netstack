#include "utils.h"

#include <arpa/inet.h>

uint16_t calcInternetChecksum16(const void *data, int len) {
  const uint8_t *d = (const uint8_t *)data;
  uint32_t sum = 0;
  for (int i = 0; i + 1 < len; i += 2) {
    uint16_t x = ((uint16_t)d[i] << 8 | d[i + 1]);
    sum += x;
    sum = (sum + (sum >> 16)) & 0xFFFF;
  }
  return htons(~sum);
}
