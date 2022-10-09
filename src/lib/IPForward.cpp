#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <sys/time.h>

#include "log.h"

#include "IPForward.h"
#include "ICMP.h"

IPForward::IPForward(IP &ip_) : ip(ip_), ipHandler(*this) {}

int IPForward::setup() {
  ip.addRecvCallback(&ipHandler);
  return 0;
}

IPForward::IPHandler::IPHandler(IPForward &ipForward_)
    : IP::RecvCallback(true, -1), ipForward(ipForward_) {}

int IPForward::IPHandler::handle(const void *buf, int len, const Info &info) {
  const auto &origHeader = *(const IP::Header *)buf;

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

  // Assuming the forwarding time much less than 1s.
  if (origHeader.timeToLive <= procTime) {
    // drop.
    ipForward.ip.icmp.sendTimeExceeded(buf, len, info);
    return 0;
  }

  void *newBuf = malloc(len);
  if (!newBuf) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  memcpy(newBuf, buf, len);
  auto &newHeader = *(IP::Header *)newBuf;
  newHeader.timeToLive -= procTime;

  int rc = ipForward.ip.sendPacketWithHeader(newBuf, len);
  free(newBuf);
  return rc;
}
