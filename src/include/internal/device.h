#ifndef INTERNAL_DEVICE_H
#define INTERNAL_DEVICE_H

#include <netinet/ether.h>

#include <pcap/pcap.h>

namespace netstack_internal {

struct Device {
  char *name;
  ether_addr eth_addr;
  pcap_t *handle;

  Device(const char *name_, ether_addr eth_addr_, pcap_t *handle_);
  Device(const Device &) = delete;

  ~Device();
};

extern int nDevices, nDevicesReserved;
extern Device *devices;

} // namespace netstack_internal

#endif
