#ifndef NETSTACK_UTILS_H
#define NETSTACK_UTILS_H

#include <cinttypes>
#include <vector>

template <typename T>
using Vector = std::vector<T>;

uint16_t calcInternetChecksum16(const void *data, int len);

#endif
