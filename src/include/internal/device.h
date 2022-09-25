#ifndef INTERNAL_DEVICE_H
#define INTERNAL_DEVICE_H

#include <thread>

#include <netinet/ether.h>

#include <pcap/pcap.h>

namespace netstack_internal {

struct Device {
  char *name;
  ether_addr eth_addr;
  pcap_t *handle;
  std::thread *recvThread;
};

extern int nDevices, nDevicesReserved;
extern Device *devices;

void deviceRecvAction(pcap_t *handle, int id);

} // namespace netstack_internal

#endif
