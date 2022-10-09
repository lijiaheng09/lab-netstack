#include "common.h"

Ethernet::Device *findDeviceByName(const char *name) {
  Ethernet::Device *d;
  invoke([&]() { d = ethernet.findDeviceByName(name); });
  if (!d) {
    printf("Device not found: %s\n", name);
  }
  return d;
}
