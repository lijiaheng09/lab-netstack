#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "log.h"

#include "IPForward.h"

IPForward::IPForward(IP &ip_)
    : ip(ip_), ipHandler(*this) {}

int IPForward::setup() {
  ip.addRecvCallback(&ipHandler);
  return 0;
}

IPForward::IPHandler::IPHandler(IPForward &ipForward_)
    : IP::RecvCallback(true, -1), ipForward(ipForward_) {}

int IPForward::IPHandler::handle(const void *buf, int len) {
  const auto &origHeader = *(const IP::Header *)buf;

  if (ipForward.ip.findDeviceByAddr(origHeader.dst)) {
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
  auto &newHeader = *(IP::Header *)newBuf;
  newHeader.timeToLive -= 1;

  int rc = ipForward.ip.sendPacketWithHeader(newBuf, len);
  free(newBuf);
  return rc;
}
