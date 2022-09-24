#include <cstring>

#include <pcap/pcap.h>

#include "device.h"

#include "internal/device.h"

namespace netstack_internal {

int Device::num = 0;
Device *devices = nullptr;

Device::Device(const char *name_, pcap_t *handle_, Device *next_) {
  id = num++;
  name = new char[strlen(name_) + 1];
  strcpy(name, name_);
  handle = handle_;
  next = next_;
}

Device::~Device() {
  delete[] name;
}

} // namespace netstack_internal

using namespace netstack_internal;

// see pcap_set_timeout
constexpr int BUFFER_TIMEOUT = 1000;

int addDevice(const char *device) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if (findDevice(device) != -1)
    return -1; // duplicated device

  pcap_t *handle = pcap_create(device, errbuf);
  if (handle == nullptr ||
      pcap_set_timeout(handle, BUFFER_TIMEOUT) ||
      pcap_activate(handle))
    return -1;

  devices = new Device(device, handle, devices);
  return devices->id;
}

int findDevice(const char *device) {
  for (Device *p = devices; p; p = p->next)
    if (strcmp(p->name, device) == 0)
      return p->id;
  return -1;
}
