#ifndef NETSTACK_UTILS_H
#define NETSTACK_UTILS_H

#include <cinttypes>
#include <vector>

template <typename T>
using Vector = std::vector<T>;

/**
 * @brief Calculate the 16-bit Internet checksum.
 * 
 * @param data Pointer to the data to be checksummed.
 * @param len Length of the data.
 * @return The checksum of the data, in network endian.
 */
uint16_t calcInternetChecksum16(const void *data, int len);

#endif
