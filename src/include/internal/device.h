#ifndef INTERNAL_DEVICE_H
#define INTERNAL_DEVICE_H

#include <netinet/ether.h>

#include <pcap/pcap.h>

namespace netstack_internal {

struct Device {
  char *name;
  ether_addr eth_addr;
  pcap_t *handle;
};

extern int nDevices, nDevicesReserved;
extern Device *devices;

} // namespace netstack_internal

#endif
