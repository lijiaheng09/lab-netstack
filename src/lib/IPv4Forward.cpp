#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "log.h"

#include "IPv4Forward.h"

IPv4Forward::IPv4Forward(IPv4 &ipv4Layer_)
    : ipv4Layer(ipv4Layer_), ipv4Handler(*this) {}

int IPv4Forward::setup() {
  ipv4Layer.addRecvCallback(&ipv4Handler);
  return 0;
}

IPv4Forward::IPv4Handler::IPv4Handler(IPv4Forward &service_)
    : IPv4::RecvCallback(true, -1), service(service_) {}

int IPv4Forward::IPv4Handler::handle(const void *buf, int len) {
  const auto &origHeader = *(const IPv4::Header *)buf;

  if (service.ipv4Layer.findDeviceByAddr(origHeader.dst)) {
    // no need to forward.
    return 0;
  }

  // Assuming the forwarding time much less than 1s.
  if (origHeader.timeToLive <= 1) {
    // drop.
    // TODO: send an ICMP packet.
    return 0;
  }

  void *newBuf = malloc(len);
  if (!newBuf) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  memcpy(newBuf, buf, len);
  auto &newHeader = *(IPv4::Header *)newBuf;
  newHeader.timeToLive -= 1;
  int rc = service.ipv4Layer.sendPacketWithHeader(newBuf, len);
  free(newBuf);
  return rc;
}
