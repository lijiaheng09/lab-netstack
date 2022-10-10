#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <sys/time.h>

#include "log.h"

#include "IPForward.h"
#include "ICMP.h"

IPForward::IPForward(IP &ip_) : ip(ip_), isUp(false), ipHandler(*this) {}

int IPForward::setup() {
  if (isUp) {
    ERRLOG("IP forwarding is already up.\n");
    return 1;
  }
  isUp = true;
  ip.addRecvCallback(&ipHandler);
  return 0;
}

IPForward::IPHandler::IPHandler(IPForward &ipForward_)
    : IP::RecvCallback(true, -1), ipForward(ipForward_) {}

int IPForward::IPHandler::handle(const void *data, int dataLen,
                                 const Info &info) {
  const void *packet = info.netHeader;
  const auto &origHeader = *info.netHeader;

  if (info.endDevice) {
    /*
     * no need to forward.
     * TODO: forward a direct broadcast in LAN more than 2 devices (like a
     * normal "router"), which is not the case we are facing now.
     */
    return 0;
  }

  int procTime = 1;

  timeval cur;
  if (gettimeofday(&cur, nullptr) == 0) {
    procTime = cur.tv_sec - info.ts.tv_sec;
    if (cur.tv_usec >= info.ts.tv_usec)
      procTime++;
  }
  
  int packetLen = ntohs(origHeader.totalLength);

  // Assuming the forwarding time much less than 1s.
  if (origHeader.timeToLive <= procTime) {
    // drop.
    ipForward.ip.icmp.sendTimeExceeded(&origHeader, packetLen, info);
    return 0;
  }

  void *newBuf = malloc(packetLen);
  if (!newBuf) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  memcpy(newBuf, packet, packetLen);
  auto &newHeader = *(IP::Header *)newBuf;
  newHeader.timeToLive -= procTime;

  int rc = ipForward.ip.sendPacketWithHeader(newBuf, packetLen);
  free(newBuf);
  return rc;
}
