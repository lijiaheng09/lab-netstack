#ifndef INTERNAL_DEVICE_H
#define INTERNAL_DEVICE_H

#include <pcap/pcap.h>

namespace netstack_internal {

struct Device {
  char *name;
  pcap_t *handle;

  Device(const char *name_, pcap_t *handle_);
  Device(const Device &) = delete;

  ~Device();
};

extern int nDevices, nDevicesReserved;
extern Device *devices;

} // namespace netstack_internal

#endif
