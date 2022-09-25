#include <cstdlib>
#include <cstring>
#include <new>

#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include "device.h"

#include "internal/device.h"

namespace netstack_internal {

std::shared_timed_mutex mutexDevices;
int nDevices = 0, nDevicesReserved = 0;
Device *devices = nullptr;

} // namespace netstack_internal

using namespace netstack_internal;

// see pcap_set_timeout
// static constexpr int BUFFER_TIMEOUT = 1000;

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
  if (!handle ||
      // pcap_set_timeout(handle, BUFFER_TIMEOUT) != 0 ||
      pcap_set_immediate_mode(handle, 1) != 0 ||
      pcap_activate(handle) != 0) {
    if (handle)
      pcap_close(handle);
    return -1;
  }

  mutexDevices.lock();

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

  char *nameCopy = (char *)malloc(strlen(device) + 1);
  if (!nameCopy) {
    pcap_close(handle);
    return -1;
  }
  strcpy(nameCopy, device);

  int id = nDevices;

  devices[nDevices++] = {
    name: nameCopy,
    ethAddr: addr,
    handle: handle,
    recvThread: new std::thread(deviceRecvAction, handle, id)
  };
  devices[id].recvThread->detach();

  mutexDevices.unlock();

  return id;
}

int findDevice(const char *device) {
  mutexDevices.lock_shared();
  int ret = -1;
  for (int i = 0; i < nDevices; i++)
    if (strcmp(devices[i].name, device) == 0) {
      ret = i;
      break;
    }
  mutexDevices.unlock_shared();
  return ret;
}
