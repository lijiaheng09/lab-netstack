#include <cstring>

#include <pcap/pcap.h>

#include "NetStack.h"
#include "log.h"

NetStack::Device::Device(pcap_t *p_, const char *name_, int linkType_)
    : p(p_), id(-1), name(new char[strlen(name_) + 1]), linkType(linkType_) {
  strcpy(name, name_);
}

NetStack::Device::~Device() {
  pcap_close(p);
  delete[] name;
}

int NetStack::Device::sendFrame(void *buf, int len) {
  return pcap_sendpacket(p, (u_char *)buf, len);
}

int NetStack::addDevice(Device *device) {
  device->id = (int)devices.size();
  devices.push_back(device);
  return device->id;
}

NetStack::Device *NetStack::findDeviceByName(const char *name) {
  for (auto *d : devices)
    if (strcmp(d->name, name) == 0)
      return d;
  return nullptr;
}

NetStack::RecvCallback::RecvCallback(int linkType_) : linkType(linkType_) {}

void NetStack::addRecvCallback(RecvCallback *callback) {
  callbacks.push_back(callback);
}

int NetStack::handleFrame(const void *buf, int len, Device *device) {
  int rc = 0;
  for (auto *c : callbacks)
    if (c->linkType == -1 || device->linkType == c->linkType)
      if (c->handle(buf, len, device) != 0)
        rc = -1;
  return rc;
}

int NetStack::setup() {
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
  if (rc != 0)
    ERRLOG("pcap_init error: %s\n", errbuf);
  return rc;
}

struct PcapHandleArgs {
  NetStack *stack;
  NetStack::Device *device;
};

static void handlePcap(u_char *user, const pcap_pkthdr *h,
                       const u_char *bytes) {
  PcapHandleArgs args = *(PcapHandleArgs *)user;
  if (h->caplen != h->len) {
    ERRLOG("Incomplete frame captured (device %s): %d/%d.\n", args.device->name,
           h->caplen, h->len);
    return;
  }

  args.stack->handleFrame((void *)bytes, h->len, args.device);
}

int NetStack::loop() {
  char errbuf[PCAP_ERRBUF_SIZE];
  for (auto *d : devices) {
    int rc;

    rc = pcap_setnonblock(d->p, 1, errbuf);
    if (rc != 0) {
      ERRLOG("pcap_setnonblock (device %s) error: %s\n", d->name, errbuf);
      return rc;
    }
    rc = pcap_setdirection(d->p, PCAP_D_IN);
    if (rc != 0) {
      ERRLOG("pcap_setdirection (device %s) error: %s\n", d->name,
             pcap_geterr(d->p));
      return rc;
    }
  }

  while (1) {
    for (auto *d : devices) {
      PcapHandleArgs args{stack : this, device : d};
      int rc = pcap_dispatch(d->p, -1, handlePcap, (u_char *)&args);
      if (rc < 0) {
        if (rc == PCAP_ERROR)
          ERRLOG("pcap_dispatch (device %s) error: %s\n", d->name,
                 pcap_geterr(d->p));
        return rc;
      }
    }
  }

  return 0;
}
