#ifndef INTERNAL_DEVICE_H
#define INTERNAL_DEVICE_H

#include <pcap/pcap.h>

namespace netstack_internal {

struct Device {
  static int num;

  int id;
  char *name;
  pcap_t *handle;
  Device *next;

  Device(const char *name_, pcap_t *handle_, Device *next_);
  Device(const Device &) = delete;

  ~Device();
};

extern Device *devices;

} // namespace netstack_internal

#endif
