#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <arpa/inet.h>

#include "log.h"

#include "ICMP.h"

constexpr int ICMP::PROTOCOL_ID = 1;

ICMP::ICMP(IP &ip_) : ip(ip_), ipHandler(*this) {}

int ICMP::sendTimeExceeded(const void *orig, int origLen,
                           const IP::RecvCallback::Info &info) {
  const IP::Header &origHeader = *(const IP::Header *)orig;

  int origHdrLen = (origHeader.versionAndIHL & 0x0F) * 4;
  int dataLen = ntohs(origHeader.totalLength);
  if (dataLen > origHdrLen + 64)
    dataLen = origHdrLen + 64;
  int msgLen = sizeof(Header) + dataLen;

  IP::Addr src;
  int rc = ip.getAnyAddr(info.linkDevice, src);
  if (rc < 0) {
    ERRLOG("No IP address on the host.\n");
    return rc;
  }

  void *msg = malloc(msgLen);
  if (!msg) {
    ERRLOG("malloc error: %s\n", strerror(errno));
    return -1;
  }

  Header &header = *(Header *)msg;
  header = Header{type : 11, code : 0, checksum : 0, info : 0};
  memcpy(&header + 1, orig, dataLen);
  header.checksum = calcInternetChecksum16(msg, msgLen);
#ifdef NETSTACK_DEBUG
  assert(calcInternetChecksum16(msg, msgLen) == 0);
#endif

  rc = ip.sendPacket(msg, msgLen, src, origHeader.src, PROTOCOL_ID);
  free(msg);
  return rc;
}

int ICMP::setup() {
  ip.addRecvCallback(&ipHandler);
  return 0;
}

ICMP::IPHandler::IPHandler(ICMP &icmp_)
    : icmp(icmp_), IP::RecvCallback(false, PROTOCOL_ID) {}

int ICMP::IPHandler::handle(const void *buf, int len, const Info &info) {
  return 0;
}
