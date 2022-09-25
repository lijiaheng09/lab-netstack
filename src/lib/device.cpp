#include <cstdlib>
#include <cstring>
#include <new>

#include <pcap/pcap.h>

#include "device.h"

#include "internal/device.h"

namespace netstack_internal {

int nDevices = 0, nDevicesReserved = 0;
Device *devices = nullptr;

Device::Device(const char *name_, pcap_t *handle_) : handle(handle_) {
  name = new char[strlen(name_) + 1];
  strcpy(name, name_);
}

Device::~Device() {
  delete[] name;
}

} // namespace netstack_internal

using namespace netstack_internal;

// see pcap_set_timeout
static constexpr int BUFFER_TIMEOUT = 1000;

int addDevice(const char *device) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if (findDevice(device) != -1)
    return -1; // duplicated device

  pcap_t *handle = pcap_create(device, errbuf);
  if (handle == nullptr ||
      pcap_activate(handle)) {
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

  new(&devices[nDevices++]) Device(device, handle);

  return nDevices - 1;
}

int findDevice(const char *device) {
  for (int i = 0; i < nDevices; i++)
    if (strcmp(devices[i].name, device) == 0)
      return i;
  return -1;
}
