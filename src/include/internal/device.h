#ifndef INTERNAL_DEVICE_H
#define INTERNAL_DEVICE_H

#include <thread>
#include <shared_mutex>

#include <netinet/ether.h>

#include <pcap/pcap.h>

namespace netstack_internal {

struct Device {
  char *name;
  ether_addr ethAddr;
  pcap_t *handle;
  std::thread *recvThread;
};

extern std::shared_timed_mutex mutexDevices;
extern int nDevices, nDevicesReserved;
extern Device *devices;

void deviceRecvAction(pcap_t *handle, int id);

} // namespace netstack_internal

#endif
