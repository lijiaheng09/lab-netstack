#include "utils.h"

#include <arpa/inet.h>

uint16_t csum16(const void *data, size_t len, uint16_t init) {
  const uint8_t *d = (const uint8_t *)data;
  uint32_t sum = ntohs(init);
  for (int i = 0; i + 1 < len; i += 2) {
    uint16_t x = ((uint16_t)d[i] << 8 | d[i + 1]);
    sum += x;
    sum = (sum + (sum >> 16)) & 0xFFFF;
  }
  if (len % 2 != 0) {
    sum += (uint16_t)d[len - 1] << 8;
    sum = (sum + (sum >> 16)) & 0xFFFF;
  }
  return htons(~sum);
}
