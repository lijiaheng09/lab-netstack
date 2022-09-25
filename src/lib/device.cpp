#include <cstdlib>
#include <cstring>
#include <new>

#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include "device.h"

#include "internal/device.h"

namespace netstack_internal {

int nDevices = 0, nDevicesReserved = 0;
Device *devices = nullptr;

Device::Device(const char *name_, ether_addr eth_addr_, pcap_t *handle_)
    : eth_addr(eth_addr_), handle(handle_) {
  name = (char *)malloc(strlen(name_) + 1);
  strcpy(name, name_);
}

Device::~Device() {
  free(name);
}

} // namespace netstack_internal

using namespace netstack_internal;

// see pcap_set_timeout
static constexpr int BUFFER_TIMEOUT = 1000;

int addDevice(const char *device) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if (findDevice(device) != -1)
    return -1; // duplicated device

  bool found = false;
  ether_addr addr;
  pcap_if_t *alldevs;
  if (pcap_findalldevs(&alldevs, errbuf) != 0)
    return -1;
  for (auto *p = alldevs; p; p = p->next)
    if (strcmp(p->name, device) == 0) {
      for (auto *a = p->addresses; a; a = a->next)
        if (a->addr && a->addr->sa_family == AF_PACKET) {
          sockaddr_ll *s = (sockaddr_ll *)a->addr;
          if (s->sll_hatype == ARPHRD_ETHER) {
            memcpy(&addr, s->sll_addr, sizeof(addr));
            found = true;
            break;
          }
        }
      if (found)
        break;
    }
  pcap_freealldevs(alldevs);
  
  if (!found)
    return -1;

  pcap_t *handle = pcap_create(device, errbuf);
  if (handle == nullptr || pcap_activate(handle)) {
    if (handle)
      pcap_close(handle);
    return -1;
  }

  if (nDevices >= nDevicesReserved) {
    if (nDevicesReserved == 0)
      nDevicesReserved = 1;
    else
      nDevicesReserved *= 2;
    devices = (Device *)realloc(devices, sizeof(Device) * nDevicesReserved);
    if (!devices) {
      pcap_close(handle);
      return -1;
    }
  }

  new (&devices[nDevices++]) Device(device, addr, handle);
  return nDevices - 1;
}

int findDevice(const char *device) {
  for (int i = 0; i < nDevices; i++)
    if (strcmp(devices[i].name, device) == 0)
      return i;
  return -1;
}
