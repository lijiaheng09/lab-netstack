#include <cstring>
#include <cstdlib>
#include <cerrno>

#include <pcap/pcap.h>

#include <linux/if_arp.h>
#include <linux/if_packet.h>

#include "log.h"

#include "Ethernet.h"

constexpr Ethernet::Addr Ethernet::BROADCAST;

Ethernet::Ethernet(NetBase &netBase_) : netBase(netBase_) {}

Ethernet::Device::Device(pcap_t *p_, const char *name_, const Addr &addr_)
    : NetBase::Device(p_, name_, LINK_TYPE), addr(addr_) {}

Ethernet::Device *Ethernet::addDeviceByName(const char *name) {
  if (netBase.findDeviceByName(name)) {
    LOG_ERR("Duplicated device: %s", name);
    return nullptr;
  }

  int rc;
  char errbuf[PCAP_ERRBUF_SIZE];
  bool found = false;
  Addr addr;

  pcap_if_t *alldevs;
  rc = pcap_findalldevs(&alldevs, errbuf);
  if (rc != 0) {
    LOG_ERR("pcap_findalldevs: %s", errbuf);
    return nullptr;
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
      if (!found)
        LOG_ERR("No Ethernet address: %s", name);
      if (found)
        break;
    }
  pcap_freealldevs(alldevs);

  if (!found) {
    LOG_ERR("No such Ethernet device: %s", name);
    return nullptr;
  }

  pcap_t *p = pcap_create(name, errbuf);
  Ethernet::Device *d;
  if (!p) {
    LOG_ERR("pcap_create(%s): %s", name, errbuf);
    return nullptr;
  }
  rc = pcap_set_immediate_mode(p, 1);
  if (rc != 0) {
    LOG_ERR_PCAP(p, "pcap_set_immediate(%s)", name);
    goto CLOSE;
  }
  rc = pcap_setnonblock(p, 1, errbuf);
  if (rc != 0) {
    LOG_ERR("pcap_setnonblock(%s): %s", name, errbuf);
    goto CLOSE;
  }
  rc = pcap_activate(p);
  if (rc != 0) {
    LOG_ERR_PCAP(p, "pcap_activate(%s)", name);
    goto CLOSE;
  }
  rc = pcap_setdirection(p, PCAP_D_IN);
  if (rc != 0) {
    LOG_ERR_PCAP(p, "pcap_setdirection(%s)", name);
    goto CLOSE;
  }

  d = new Device(p, name, addr);
  netBase.addDevice(d);
  return d;

CLOSE:
  pcap_close(p);
  return nullptr;
}

Ethernet::Device *Ethernet::findDeviceByName(const char *name) {
  return dynamic_cast<Device *>(netBase.findDeviceByName(name));
}

int Ethernet::send(const void *data, size_t dataLen, Addr dst,
                   uint16_t etherType, Device *dev) {
  if (dataLen > SIZE_MAX - sizeof(Header)) {
    LOG_ERR("Ethernet data length too large: %lu", dataLen);
    return -1;
  }

  size_t frameLen = sizeof(Header) + dataLen;
  void *frame = malloc(frameLen);
  if (!frame) {
    LOG_ERR_POSIX("malloc");
    return -1;
  }

  Header &header = *(Header *)frame;
  header = Header{.dst = dst, .src = dev->addr, .etherType = htons(etherType)};
  memcpy(&header + 1, data, dataLen);

  int rc = netBase.send(frame, frameLen, dev);
  free(frame);
  return rc;
}

void Ethernet::addOnRecv(RecvHandler handler, uint16_t etherType) {
  onRecv.insert({etherType, handler});
}

void Ethernet::handleRecv(const void *frame, size_t frameLen,
                          const NetBase::RecvInfo &info) {
  auto *device = dynamic_cast<Ethernet::Device *>(info.device);
  if (!device) {
    LOG_INFO("Unconfigured Ethernet device: %s", info.device->name);
    return;
  }

  if (frameLen < sizeof(Header)) {
    LOG_INFO("Truncated Ethernet header on device %s: %lu/%lu", device->name,
             frameLen, sizeof(Header));
    return;
  }

  const Header &header = *(const Header *)frame;
  const void *data = &header + 1;
  size_t dataLen = frameLen - sizeof(Header);
  Ethernet::RecvInfo newInfo{
      .timestamp = info.timestamp, .device = device, .linkHeader = &header};

  auto r = onRecv.equal_range(ntohs(header.etherType));
  for (auto it = r.first; it != r.second;) {
    if (it->second(data, dataLen, newInfo) == 1)
      it = onRecv.erase(it);
    else
      it++;
  }
}

int Ethernet::setup() {
  netBase.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      LINK_TYPE);
  return 0;
}
