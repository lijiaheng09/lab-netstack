#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>
#include <sys/time.h>

#include "log.h"

#include "IPForward.h"
#include "ARP.h"
#include "ICMP.h"

IPForward::IPForward(IP &ip_) : ip(ip_), isUp(false) {}

int IPForward::setup() {
  if (isUp) {
    ERRLOG("IP forwarding is already up.\n");
    return 1;
  }
  isUp = true;
  ip.addOnRecv(
      [this](auto &&...args) -> int {
        handleRecv(args...);
        return 0;
      },
      0, true);
  return 0;
}

void IPForward::handleRecv(const void *data, size_t dataLen,
                           const IP::RecvInfo &info) {
  const void *packet = info.header;
  const auto &origHeader = *info.header;

  if (info.endDevice) {
    /*
     * no need to forward.
     * TODO: forward a direct broadcast in LAN more than 2 devices (like a
     * normal "router"), which is not the case we are facing now.
     */
    return;
  }

  int procTime = 1;

  timeval cur;
  if (gettimeofday(&cur, nullptr) == 0) {
    procTime = cur.tv_sec - info.l2.timestamp.tv_sec;
    if (cur.tv_usec >= info.l2.timestamp.tv_usec)
      procTime++;
  }

  int packetLen = ntohs(origHeader.totalLength);

  // Assuming the forwarding time much less than 1s.
  if (origHeader.timeToLive <= procTime) {
    // drop.
    ip.icmp.sendTimeExceeded(&origHeader, packetLen, info);
    return;
  }

  void *newBuf = malloc(packetLen);
  if (!newBuf) {
    LOG_ERR_POSIX("malloc");
    return;
  }

  memcpy(newBuf, packet, packetLen);
  auto &newHeader = *(IP::Header *)newBuf;
  newHeader.timeToLive -= procTime;

  int rc = ip.sendWithHeader(newBuf, packetLen, {});
  if (rc == E_WAIT_FOR_TRYAGAIN) {
    ip.addWait(newHeader.dst, [=](bool succ) {
      if (succ)
        ip.sendWithHeader(newBuf, packetLen, {});
      free(newBuf);
    });
  } else {
    free(newBuf);
  }
}
