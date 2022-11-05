#include <cstring>
#include <cstdlib>
#include <climits>

#include <pcap/pcap.h>

#include "log.h"

#include "NetBase.h"

NetBase::Device::Device(pcap_t *p_, const char *name_, int linkType_)
    : p(p_), name(strdup(name_)), linkType(linkType_) {}

NetBase::Device::~Device() {
  pcap_close(p);
  free(const_cast<char *>(name));
}

void NetBase::addDevice(Device *device) {
  devices.push_back(device);
}

NetBase::Device *NetBase::findDeviceByName(const char *name) {
  for (auto *d : devices)
    if (strcmp(d->name, name) == 0)
      return d;
  return nullptr;
}

int NetBase::send(const void *buf, size_t len, Device *dev) {
  if (len > INT_MAX) {
    LOG_ERR("Frame length too large: %lu", len);
    return -1;
  }
  int rc = pcap_sendpacket(dev->p, (const u_char *)buf, (int)len);
  if (rc != 0)
    LOG_ERR_PCAP(dev->p, "pcap_sendpacket(%s)", dev->name);
  return rc;
}

void NetBase::addOnRecv(RecvHandler handler, int linkType) {
  onRecv.insert({linkType, handler});
}

void NetBase::handleRecv(const void *buf, size_t len, const RecvInfo &info) {
  auto r = onRecv.equal_range(info.device->linkType);
  for (auto it = r.first; it != r.second;) {
    if (it->second(buf, len, info) == 1)
      it = onRecv.erase(it);
    else
      it++;
  }
}

int NetBase::setup() {
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
  if (rc != 0)
    LOG_ERR("pcap_init: %s\n", errbuf);
  return rc;
}

struct PcapHandleArgs {
  NetBase *netBase;
  NetBase::Device *device;
};

static void handlePcap(u_char *user, const pcap_pkthdr *h,
                       const u_char *bytes) {
  PcapHandleArgs args = *(PcapHandleArgs *)user;
  if (h->caplen != h->len) {
    LOG_ERR("Incomplete frame captured on %s: %d/%d", args.device->name,
            h->caplen, h->len);
    return;
  }

  NetBase::RecvInfo info = {.device = args.device, .timestamp = h->ts};
  args.netBase->handleRecv(bytes, h->len, info);
}

void NetBase::addLoopCallback(LoopCallback *callback) {
  loopCallbacks.push_back(callback);
}

int NetBase::loop() {
  while (1) {
    for (auto *d : devices) {
      PcapHandleArgs args{netBase : this, device : d};
      int rc = pcap_dispatch(d->p, -1, handlePcap, (u_char *)&args);
      if (rc < 0) {
        if (rc == PCAP_ERROR)
          ERRLOG("pcap_dispatch (device %s) error: %s\n", d->name,
                 pcap_geterr(d->p));
        return rc;
      }
    }

    for (auto *c : loopCallbacks) {
      int rc = c->handle();
      if (rc < 0)
        return rc;
      else if (rc > 0)
        return 0;
    }
  }

  return 0;
}
