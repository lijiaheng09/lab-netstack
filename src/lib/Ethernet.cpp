#include <cstring>

#include <pcap/pcap.h>

#include <linux/if_arp.h>
#include <linux/if_packet.h>

#include "Ethernet.h"
#include "log.h"

constexpr int Ethernet::LINK_TYPE = DLT_EN10MB;

Ethernet::Ethernet(NetStack &stack_) : stack(stack_), netstackHandler(*this) {}

Ethernet::Device::Device(pcap_t *p_, const char *name_, const Addr &addr_)
    : NetStack::Device(p_, name_, Ethernet::LINK_TYPE), addr(addr_) {}

int Ethernet::addDeviceByName(const char *name) {
  if (stack.findDeviceByName(name)) {
    ERRLOG("Duplicated device: %s\n", name);
    return -1;
  }

  int rc;
  char errbuf[PCAP_ERRBUF_SIZE];
  bool found = false;
  Addr addr;

  pcap_if_t *alldevs;
  rc = pcap_findalldevs(&alldevs, errbuf);
  if (rc != 0) {
    ERRLOG("pcap_findalldevs error: %s\n", errbuf);
    return rc;
  }
  for (auto *d = alldevs; d; d = d->next)
    if (strcmp(d->name, name) == 0) {
      for (auto *a = d->addresses; a; a = a->next)
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

  if (!found) {
    ERRLOG("Device not found: %s\n", name);
    return -1;
  }

  pcap_t *p = pcap_create(name, errbuf);
  if (!p) {
    ERRLOG("pcap_create (device %s) error: %s\n", name, errbuf);
    return -1;
  }
  rc = pcap_set_immediate_mode(p, 1);
  if (rc != 0) {
    ERRLOG("pcap_set_immediate (device %s) error: %s\n", name, pcap_geterr(p));
    pcap_close(p);
    return -1;
  }
  return stack.addDevice(new Device(p, name, addr));
}

Ethernet::Device *Ethernet::findDeviceByName(const char *name) {
  return dynamic_cast<Device *>(stack.findDeviceByName(name));
}

Ethernet::NetStackHandler::NetStackHandler(Ethernet &ethernetLayer_)
    : NetStack::RecvCallback(LINK_TYPE), ethernetLayer(ethernetLayer_) {}

int Ethernet::NetStackHandler::handle(const void *buf, int len, NetStack::Device *device) {
  return 0;
}
